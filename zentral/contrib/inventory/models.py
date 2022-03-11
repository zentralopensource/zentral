import base64
from collections import Counter
from datetime import datetime, timedelta
import logging
import re
import urllib.parse
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.contrib.postgres.fields import ArrayField, JSONField
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.urls import reverse
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import connection, IntegrityError, models, transaction
from django.db.models import Count, F, Q, Max
from django.utils import timezone
from django.utils.crypto import get_random_string
from django.utils.functional import cached_property
from django.utils.text import slugify
from django.utils.translation import ugettext_lazy as _
from zentral.conf import settings
from zentral.core.compliance_checks.utils import get_machine_compliance_check_statuses
from zentral.core.incidents.models import MachineIncident, Status
from zentral.utils.model_extras import find_all_related_objects
from zentral.utils.mt_models import AbstractMTObject, prepare_commit_tree, MTObjectManager, MTOError
from .conf import (has_deb_packages,
                   update_ms_tree_platform, update_ms_tree_type,
                   PLATFORM_CHOICES, PLATFORM_CHOICES_DICT,
                   TYPE_CHOICES, TYPE_CHOICES_DICT)
from .exceptions import EnrollmentSecretVerificationFailed

logger = logging.getLogger('zentral.contrib.inventory.models')


class MetaBusinessUnitManager(models.Manager):
    def get_or_create_with_bu_key_and_name(self, key, name):
        try:
            mbu = self.filter(businessunit__key=key)[0]
        except IndexError:
            mbu = MetaBusinessUnit(name=name)
            mbu.save()
        return mbu

    def available_for_api_enrollment(self):
        return self.distinct().filter(businessunit__source__module='zentral.contrib.inventory')


class MetaBusinessUnit(models.Model):
    """The object to link the different BusinessUnits."""
    name = models.TextField()

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = MetaBusinessUnitManager()

    def __str__(self):
        return self.name

    class Meta:
        ordering = ('name',)

    def get_absolute_url(self):
        return reverse('inventory:mbu_machines', args=(self.id,))

    def get_current_business_units(self):
        # !!! api enrollment business unit excluded !!!
        return BusinessUnit.objects.current().exclude(
            source__module='zentral.contrib.inventory').filter(meta_business_unit=self)

    def api_enrollment_business_units(self):
        return self.businessunit_set.filter(source__module='zentral.contrib.inventory').order_by('-id')

    def api_enrollment_enabled(self):
        return self.api_enrollment_business_units().count() > 0

    def create_enrollment_business_unit(self):
        reference = "MBU{}".format(self.id)
        b, created = BusinessUnit.objects.commit({'source': {'module': 'zentral.contrib.inventory',
                                                  'name': 'inventory'},
                                                  'reference': reference,
                                                  'name': reference},
                                                 meta_business_unit=self)
        if created:
            b.set_meta_business_unit(self)
        return b

    def tags(self):
        tags = list(mbut.tag for mbut in self.metabusinessunittag_set.select_related('tag'))
        tags.sort(key=lambda t: (t.meta_business_unit is None, str(t).upper()))
        return tags

    def serialize(self):
        return {"name": self.name,
                "pk": self.pk}

    def can_be_deleted(self):
        for related_objects in find_all_related_objects(self):
            if related_objects.objects_count:
                if related_objects.name == "businessunit":
                    # OK to delete if all the business units can be deleted
                    for bu in related_objects.objects:
                        if not bu.can_be_deleted():
                            return False
                    continue
                else:
                    return False
        return True

    def delete(self, *args, **kwargs):
        if not self.can_be_deleted():
            raise ValueError("MBU {} cannot be deleted".format(self.pk))
        for b in self.businessunit_set.all():
            b.delete()
        super().delete(*args, **kwargs)


class SourceManager(MTObjectManager):
    def current_machine_group_sources(self):
        return (self.filter(machinegroup__machinesnapshot__currentmachinesnapshot__isnull=False)
                    .distinct()
                    .order_by("module", "name"))

    def current_business_unit_sources(self):
        return (self.filter(businessunit__machinesnapshot__currentmachinesnapshot__isnull=False)
                    .distinct()
                    .order_by("module", "name"))

    def current_machine_snapshot_sources(self):
        return (self.filter(currentmachinesnapshot__isnull=False)
                    .distinct()
                    .order_by("module", "name"))

    def current_macos_apps_sources(self):
        # can get really expensive if there are a lot of machines and apps
        # it is recommended to use current_machine_snapshot_sources() instead
        return (self.filter(machinesnapshot__currentmachinesnapshot__isnull=False,
                            machinesnapshot__osx_app_instances__isnull=False)
                    .distinct()
                    .order_by("module", "name"))


class Source(AbstractMTObject):
    module = models.TextField()
    name = models.TextField()
    config = JSONField(blank=True, null=True)

    objects = SourceManager()

    def __str__(self):
        return self.name

    def get_display_name(self):
        # TODO: better. see also zentral.inventory.utils
        dn = [self.name]
        try:
            dn.append(self.config["host"])
        except (TypeError, KeyError):
            pass
        return "/".join(e for e in dn if e)


class Link(AbstractMTObject):
    anchor_text = models.TextField()
    url = models.CharField(max_length=200)


class AbstractMachineGroupManager(MTObjectManager):
    def current(self):
        return (self.filter(machinesnapshot__currentmachinesnapshot__isnull=False)
                    .distinct()
                    .select_related('source')
                    .order_by('source__module', 'name'))


class AbstractMachineGroup(AbstractMTObject):
    source = models.ForeignKey(Source, on_delete=models.PROTECT)
    reference = models.TextField()
    key = models.CharField(max_length=40, db_index=True)
    name = models.TextField()
    links = models.ManyToManyField(Link)

    objects = AbstractMachineGroupManager()
    mt_excluded_fields = ('key',)

    class Meta:
        abstract = True

    def generate_key(self):
        source_dict = self.source.serialize()
        source_dict.pop('name')
        data = {'source': source_dict,
                'reference': self.reference}
        prepare_commit_tree(data)
        return data['mt_hash']

    def save(self, *args, **kwargs):
        self.key = self.generate_key()
        super(AbstractMachineGroup, self).save()

    def get_short_key(self):
        return self.key[:8]


class BusinessUnit(AbstractMachineGroup):
    meta_business_unit = models.ForeignKey(MetaBusinessUnit, on_delete=models.PROTECT)
    mt_excluded_fields = ('key', 'meta_business_unit')

    def __str__(self):
        if self.is_api_enrollment_business_unit():
            return "{} API enrollment".format(self.meta_business_unit.name)
        else:
            return self.name

    def save(self, *args, **kwargs):
        self.key = self.generate_key()
        # get or create the corresponding MetaBusinessUnit
        # there must always be a MetaBusinessUnit for every BusinessUnit in the inventory
        # MetaBusinessUnits can be edited in the UI, not the BusinessUnits directly
        # Many BusinessUnits can be linked to a single MetaBusinessUnit to show that they are equivalent.
        mbu = kwargs.get('meta_business_unit', None)
        if not mbu:
            mbu = MetaBusinessUnit.objects.get_or_create_with_bu_key_and_name(self.key, self.name)
        self.meta_business_unit = mbu
        super(BusinessUnit, self).save(*args, **kwargs)

    def set_meta_business_unit(self, mbu):
        self.meta_business_unit = mbu
        super(BusinessUnit, self).save()

    def is_api_enrollment_business_unit(self):
        return self.source.module == "zentral.contrib.inventory"

    def get_name_display(self):
        if self.is_api_enrollment_business_unit():
            return "{} - API enrollment".format(self.meta_business_unit)
        else:
            return self.name

    def can_be_detached(self):
        return (not self.is_api_enrollment_business_unit() and
                self.meta_business_unit.get_current_business_units().count() > 1)

    def detach(self):
        if not self.can_be_detached():
            return self.meta_business_unit
        new_mbu = MetaBusinessUnit.objects.create(name=self.name)
        self.set_meta_business_unit(new_mbu)
        return new_mbu

    def can_be_deleted(self):
        return not self.machinesnapshot_set.count()


class MachineGroup(AbstractMachineGroup):
    machine_links = models.ManyToManyField(Link, related_name="+")  # tmpl for links to machine in a group


class OSVersion(AbstractMTObject):
    name = models.TextField(blank=True, null=True)
    major = models.PositiveIntegerField()
    minor = models.PositiveIntegerField(blank=True, null=True)
    patch = models.PositiveIntegerField(blank=True, null=True)
    build = models.TextField(blank=True, null=True)

    def __str__(self):
        items = [self.get_number_display()]
        if self.name:
            items.insert(0, self.name)
        if self.build:
            items.append("({})".format(self.build))
        return " ".join(items)

    def get_number_display(self):
        return ".".join((str(i) for i in (self.major, self.minor, self.patch) if i is not None))


class SystemInfo(AbstractMTObject):
    computer_name = models.TextField(blank=True, null=True)
    hostname = models.TextField(blank=True, null=True)
    hardware_model = models.TextField(blank=True, null=True)
    hardware_serial = models.TextField(blank=True, null=True)
    cpu_type = models.TextField(blank=True, null=True)
    cpu_subtype = models.TextField(blank=True, null=True)
    cpu_brand = models.TextField(blank=True, null=True)
    cpu_physical_cores = models.PositiveIntegerField(blank=True, null=True)
    cpu_logical_cores = models.PositiveIntegerField(blank=True, null=True)
    physical_memory = models.BigIntegerField(blank=True, null=True)


class Disk(AbstractMTObject):
    name = models.TextField()
    size = models.BigIntegerField()


class NetworkInterface(AbstractMTObject):
    interface = models.TextField(blank=False, null=False)
    mac = models.CharField(max_length=23, blank=False, null=False)  # 48 or 64 bit with separators
    address = models.GenericIPAddressField(blank=True, null=True, unpack_ipv4=True)
    mask = models.GenericIPAddressField(blank=True, null=True, unpack_ipv4=True)
    broadcast = models.GenericIPAddressField(blank=True, null=True, unpack_ipv4=True)

    class Meta:
        ordering = ('interface',)

    def get_mac_organization(self):
        mac = self.mac.replace(":", "").upper()
        assignments = [mac[:length] for length in (9, 7, 6)]
        found_assignments = list(MACAddressBlockAssignment.objects.select_related("organization")
                                 .filter(assignment__in=assignments))
        if not found_assignments:
            return None
        found_assignments.sort(key=lambda a: len(a.assignment), reverse=True)
        return found_assignments[0].organization


class OSXAppManager(MTObjectManager):
    def current(self):
        return self.distinct().filter(osxappinstance__machinesnapshot__currentmachinesnapshot__isnull=False)


class OSXApp(AbstractMTObject):
    bundle_id = models.TextField(db_index=True, blank=True, null=True)
    bundle_name = models.TextField(db_index=True, blank=True, null=True)
    bundle_display_name = models.TextField(blank=True, null=True)
    bundle_version = models.TextField(blank=True, null=True)
    bundle_version_str = models.TextField(blank=True, null=True)

    objects = OSXAppManager()

    def __str__(self):
        return " ".join(s for s in (self.bundle_display_name or self.bundle_name, self.bundle_version_str) if s)

    def sources(self):
        return (Source.objects.distinct()
                .filter(machinesnapshot__osx_app_instances__app=self)
                .order_by('module', 'name'))

    def get_sources_for_display(self):
        return " ".join(s.name for s in self.sources())

    def current_instances(self):
        return (self.osxappinstance_set.filter(machinesnapshot__currentmachinesnapshot__isnull=False)
                                       .annotate(machinesnapshot_num=Count('machinesnapshot')))

    def all_names(self):
        if self.bundle_display_name:
            yield self.bundle_display_name
        if self.bundle_name and self.bundle_name != self.bundle_display_name:
            yield self.bundle_name

    def all_versions(self):
        if self.bundle_version_str:
            yield self.bundle_version_str
        if self.bundle_version and self.bundle_version != self.bundle_version_str:
            yield self.bundle_version


class Certificate(AbstractMTObject):
    common_name = models.TextField(blank=True, null=True)
    organization = models.TextField(blank=True, null=True)
    organizational_unit = models.TextField(blank=True, null=True)
    domain = models.TextField(blank=True, null=True)
    sha_1 = models.CharField(max_length=40, blank=True, null=True)
    sha_256 = models.CharField(max_length=64, blank=True, null=True, db_index=True)
    valid_from = models.DateTimeField(blank=True, null=True)
    valid_until = models.DateTimeField(blank=True, null=True)
    signed_by = models.ForeignKey('self', on_delete=models.SET_NULL, blank=True, null=True)


class OSXAppInstance(AbstractMTObject):
    app = models.ForeignKey(OSXApp, on_delete=models.PROTECT)
    bundle_path = models.TextField(blank=True, null=True)
    path = models.TextField(blank=True, null=True)
    sha_1 = models.CharField(max_length=40, blank=True, null=True)
    sha_256 = models.CharField(max_length=64, db_index=True, blank=True, null=True)
    type = models.TextField(blank=True, null=True)
    signed_by = models.ForeignKey(Certificate, on_delete=models.PROTECT, blank=True, null=True)

    def certificate_chain(self):
        chain = []
        obj = self
        while obj.signed_by:
            chain.append(obj.signed_by)
            obj = obj.signed_by
        return chain


class DebPackage(AbstractMTObject):
    name = models.TextField(blank=True, null=True)
    version = models.TextField(blank=True, null=True)
    source = models.TextField(blank=True, null=True)
    size = models.BigIntegerField(blank=True, null=True)
    arch = models.TextField(blank=True, null=True)
    revision = models.TextField(blank=True, null=True)
    status = models.TextField(blank=True, null=True)
    maintainer = models.TextField(blank=True, null=True)
    section = models.TextField(blank=True, null=True)
    priority = models.TextField(blank=True, null=True)


class Program(AbstractMTObject):
    name = models.TextField(blank=True, null=True)
    version = models.TextField(blank=True, null=True)
    language = models.TextField(blank=True, null=True)
    publisher = models.TextField(blank=True, null=True)
    identifying_number = models.TextField(blank=True, null=True)


class ProgramInstance(AbstractMTObject):
    program = models.ForeignKey(Program, on_delete=models.PROTECT)
    install_location = models.TextField(blank=True, null=True)
    install_source = models.TextField(blank=True, null=True)
    uninstall_string = models.TextField(blank=True, null=True)
    install_date = models.DateTimeField(blank=True, null=True)


# see https://developers.google.com/android/management/reference/rest/v1/enterprises.devices#ApplicationReport
class AndroidApp(AbstractMTObject):
    display_name = models.TextField()
    version_name = models.TextField()
    version_code = models.IntegerField(blank=True, null=True)
    package_name = models.TextField(blank=True, null=True)
    installer_package_name = models.TextField(blank=True, null=True)


# see https://developer.apple.com/documentation/devicemanagement/installedapplicationlistresponse/installedapplicationlistitem  # NOQA
class IOSApp(AbstractMTObject):
    name = models.TextField()
    version = models.TextField()
    ad_hoc_signed = models.BooleanField(blank=True, null=True)
    app_store_vendable = models.BooleanField(blank=True, null=True)
    beta_app = models.BooleanField(blank=True, null=True)
    bundle_size = models.BigIntegerField(blank=True, null=True)
    device_based_vpp = models.BooleanField(blank=True, null=True)
    identifier = models.TextField(blank=True, null=True)
    is_validated = models.BooleanField(blank=True, null=True)
    short_version = models.TextField(blank=True, null=True)


class TeamViewer(AbstractMTObject):
    teamviewer_id = models.TextField(blank=False, null=False)
    release = models.TextField(blank=True, null=True)
    unattended = models.NullBooleanField(blank=True, null=True)


class PuppetTrustedFacts(AbstractMTObject):
    authenticated = models.CharField(max_length=16,
                                     choices=(('remote', 'remote'),
                                              ('local', 'local'),
                                              ('false', 'false')))
    extensions = JSONField(blank=True, null=True)
    certname = models.TextField()


class PuppetCoreFacts(AbstractMTObject):
    aio_agent_version = models.TextField(blank=True, null=True)
    augeas_version = models.TextField(blank=True, null=True)
    client_version = models.TextField(blank=True, null=True)
    facter_version = models.TextField(blank=True, null=True)
    ruby_sitedir = models.TextField(blank=True, null=True)
    ruby_version = models.TextField(blank=True, null=True)
    ruby_platform = models.TextField(blank=True, null=True)


class PuppetNode(AbstractMTObject):
    environment = models.TextField()
    trusted_facts = models.ForeignKey(PuppetTrustedFacts, on_delete=models.PROTECT, blank=True, null=True)
    core_facts = models.ForeignKey(PuppetCoreFacts, on_delete=models.PROTECT, blank=True, null=True)
    extra_facts = JSONField(blank=True, null=True)


class PrincipalUserSource(AbstractMTObject):
    COMPANY_PORTAL = "COMPANY_PORTAL"
    GOOGLE_CHROME = "GOOGLE_CHROME"
    INVENTORY = "INVENTORY"
    LOGGED_IN_USER = "LOGGED_IN_USER"
    SANTA_MACHINE_OWNER = "SANTA_MACHINE_OWNER"
    TYPE_CHOICES = (
        (COMPANY_PORTAL, "Company portal"),
        (GOOGLE_CHROME, "Google Chrome"),
        (INVENTORY, "Inventory"),
        (LOGGED_IN_USER, "Logged-in user"),
        (SANTA_MACHINE_OWNER, "Santa machine owner"),
    )
    type = models.CharField(choices=TYPE_CHOICES, max_length=64)
    properties = JSONField(blank=True, null=True)


class PrincipalUser(AbstractMTObject):
    source = models.ForeignKey(PrincipalUserSource, on_delete=models.PROTECT)
    unique_id = models.TextField(db_index=True)
    principal_name = models.TextField(db_index=True)
    display_name = models.TextField(blank=True, null=True)


class Payload(AbstractMTObject):
    uuid = models.TextField()
    identifier = models.TextField(blank=True, null=True)
    display_name = models.TextField(blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    type = models.TextField(blank=True, null=True)


class Profile(AbstractMTObject):
    uuid = models.TextField(db_index=True)
    identifier = models.TextField(blank=True, null=True)
    display_name = models.TextField(blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    organization = models.TextField(blank=True, null=True)
    removal_disallowed = models.BooleanField(blank=True, null=True)
    verified = models.BooleanField(blank=True, null=True)
    install_date = models.DateTimeField(blank=True, null=True)
    payloads = models.ManyToManyField(Payload)


class MachineSnapshotManager(MTObjectManager):
    def current(self):
        return (self.select_related('business_unit__meta_business_unit',
                                    'os_version',
                                    'system_info',
                                    'teamviewer',
                                    'puppet_node')
                    .filter(currentmachinesnapshot__isnull=False))

    def current_platforms(self):
        qs = (self.filter(platform__isnull=False, currentmachinesnapshot__isnull=False)
              .values("platform").distinct())
        return sorted((rd["platform"], PLATFORM_CHOICES_DICT[rd["platform"]]) for rd in qs)

    def current_types(self):
        qs = (self.filter(type__isnull=False, currentmachinesnapshot__isnull=False)
              .values("type").distinct())
        return sorted((rd["type"], TYPE_CHOICES_DICT[rd["type"]]) for rd in qs)


class MachineSnapshot(AbstractMTObject):
    source = models.ForeignKey(Source, on_delete=models.PROTECT)
    reference = models.TextField(blank=True, null=True, db_index=True)
    serial_number = models.TextField(db_index=True)
    imei = models.CharField(max_length=18, blank=True, null=True)
    meid = models.CharField(max_length=18, blank=True, null=True)
    links = models.ManyToManyField(Link)
    business_unit = models.ForeignKey(BusinessUnit, on_delete=models.PROTECT, blank=True, null=True)
    groups = models.ManyToManyField(MachineGroup)
    os_version = models.ForeignKey(OSVersion, on_delete=models.PROTECT, blank=True, null=True)
    platform = models.CharField(max_length=32, blank=True, null=True, choices=PLATFORM_CHOICES)
    system_info = models.ForeignKey(SystemInfo, on_delete=models.PROTECT, blank=True, null=True)
    type = models.CharField(max_length=32, blank=True, null=True, choices=TYPE_CHOICES)
    disks = models.ManyToManyField(Disk)
    network_interfaces = models.ManyToManyField(NetworkInterface)
    android_apps = models.ManyToManyField(AndroidApp)
    deb_packages = models.ManyToManyField(DebPackage)
    ios_apps = models.ManyToManyField(IOSApp)
    osx_app_instances = models.ManyToManyField(OSXAppInstance)
    program_instances = models.ManyToManyField(ProgramInstance)
    profiles = models.ManyToManyField(Profile)
    teamviewer = models.ForeignKey(TeamViewer, on_delete=models.PROTECT, blank=True, null=True)
    puppet_node = models.ForeignKey(PuppetNode, on_delete=models.PROTECT, blank=True, null=True)
    principal_user = models.ForeignKey(PrincipalUser, on_delete=models.PROTECT, blank=True, null=True)
    certificates = models.ManyToManyField(Certificate)
    public_ip_address = models.GenericIPAddressField(blank=True, null=True, unpack_ipv4=True)
    extra_facts = JSONField(blank=True, null=True)

    objects = MachineSnapshotManager()

    def get_machine_str(self):
        if self.system_info and (self.system_info.computer_name or self.system_info.hostname):
            return self.system_info.computer_name or self.system_info.hostname
        else:
            return self.serial_number

    def groups_with_links(self):
        for group in self.groups.prefetch_related('links', 'machine_links').all():
            ll = []
            for link in group.links.all():
                ll.append((link.url, link.anchor_text))
            for link in group.machine_links.all():
                url = link.url
                url = url.replace('%MACHINE_SNAPSHOT_REFERENCE%', self.reference)
                ll.append((url, link.anchor_text))
            yield group, ll

    def ordered_android_apps(self):
        return self.android_apps.all().order_by('display_name', 'version_name', 'pk')

    def ordered_deb_packages(self):
        return self.deb_packages.all().order_by('name', 'version', 'pk')

    def ordered_ios_apps(self):
        return self.ios_apps.all().order_by('name', 'version', 'pk')

    def ordered_osx_app_instances(self):
        return self.osx_app_instances.select_related('app').all().order_by('app__bundle_name',
                                                                           'app__bundle_version_str',
                                                                           'bundle_path')

    def ordered_program_instances(self):
        return self.program_instances.select_related('program').all().order_by('program__name',
                                                                               'program__version',
                                                                               'install_location')

    def ordered_profiles(self):
        return self.profiles.all().order_by('identifier', 'uuid', 'pk')

    @cached_property
    def last_commit(self):
        try:
            return self.machinesnapshotcommit_set.all().order_by("-id")[0]
        except IndexError:
            pass


class MachineSnapshotCommitManager(models.Manager):
    def commit_machine_snapshot_tree(self, tree):
        last_seen = tree.pop('last_seen', None)
        if not last_seen:
            last_seen = datetime.utcnow()
        if timezone.is_aware(last_seen):
            last_seen = timezone.make_naive(last_seen)
        system_uptime = tree.pop('system_uptime', None)
        update_ms_tree_platform(tree)
        update_ms_tree_type(tree)
        machine_snapshot, _ = MachineSnapshot.objects.commit(tree)
        serial_number = machine_snapshot.serial_number
        source = machine_snapshot.source
        new_version = new_parent = None
        try:
            with transaction.atomic():
                try:
                    msc = MachineSnapshotCommit.objects.filter(serial_number=serial_number,
                                                               source=source).order_by('-version')[0]
                except IndexError:
                    new_version = 1
                else:
                    if msc.machine_snapshot != machine_snapshot \
                       or msc.last_seen != last_seen \
                       or msc.system_uptime != system_uptime:
                        new_version = msc.version + 1
                        new_parent = msc
                new_msc = None
                if new_version:
                    new_msc = MachineSnapshotCommit.objects.create(serial_number=serial_number,
                                                                   source=source,
                                                                   version=new_version,
                                                                   machine_snapshot=machine_snapshot,
                                                                   parent=new_parent,
                                                                   last_seen=last_seen,
                                                                   system_uptime=system_uptime)
                CurrentMachineSnapshot.objects.update_or_create(serial_number=serial_number,
                                                                source=source,
                                                                defaults={'machine_snapshot': machine_snapshot,
                                                                          'last_seen': last_seen})
                return new_msc, machine_snapshot, last_seen
        except IntegrityError:
            msc = MachineSnapshotCommit.objects.get(serial_number=serial_number,
                                                    source=source,
                                                    version=new_version)
            if msc.machine_snapshot == machine_snapshot:
                logger.warning("MachineSnapshotCommit race with same snapshot for "
                               "source {} and serial_number {}".format(source, serial_number))
                return None, machine_snapshot, msc.last_seen
            else:
                raise MTOError("MachineSnapshotCommit race for "
                               "source {} and serial_number {}".format(source, serial_number))


class MachineSnapshotCommit(models.Model):
    serial_number = models.TextField(db_index=True)
    source = models.ForeignKey(Source, on_delete=models.CASCADE)
    version = models.PositiveIntegerField(default=1)
    machine_snapshot = models.ForeignKey(MachineSnapshot, on_delete=models.CASCADE)
    parent = models.ForeignKey('self', on_delete=models.SET_NULL, blank=True, null=True)
    last_seen = models.DateTimeField(blank=True, null=True)
    system_uptime = models.PositiveIntegerField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = MachineSnapshotCommitManager()

    class Meta:
        unique_together = ('serial_number', 'source', 'version')

    def update_diff(self):
        if not self.parent:
            return None
        else:
            diff = self.machine_snapshot.diff(self.parent.machine_snapshot)
            if self.parent.last_seen and self.parent.last_seen != self.last_seen:
                diff["last_seen"] = {"removed": self.parent.last_seen}
            if self.last_seen and self.parent.last_seen != self.last_seen:
                diff.setdefault("last_seen", {})["added"] = self.last_seen
            return diff

    def get_system_update_for_display(self):
        if self.system_uptime:
            return str(timedelta(seconds=self.system_uptime)).strip(":0 ,")


class CurrentMachineSnapshot(models.Model):
    serial_number = models.TextField(db_index=True)
    source = models.ForeignKey(Source, on_delete=models.CASCADE)
    machine_snapshot = models.ForeignKey(MachineSnapshot, on_delete=models.CASCADE)
    last_seen = models.DateTimeField()

    class Meta:
        unique_together = ('serial_number', 'source')


class Taxonomy(models.Model):
    """A bag of tags, can be restricted to a MBU"""
    meta_business_unit = models.ForeignKey(MetaBusinessUnit, on_delete=models.CASCADE, blank=True, null=True)
    name = models.CharField(max_length=256, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        if self.meta_business_unit:
            return "{}/{}".format(self.meta_business_unit, self.name)
        else:
            return self.name

    class Meta:
        ordering = ("meta_business_unit__name", "name")

    def links(self):
        known_models = {
            Tag: ("tag", "tags", None)  # TODO: filter?
        }
        link_list = []
        for related_objects in find_all_related_objects(self):
            if related_objects.name == "meta_business_unit":
                continue
            if related_objects.objects_count:
                if related_objects.to_model in known_models:
                    label, label_plural, url = known_models[related_objects.to_model]
                    link_list.append(("{} {}".format(related_objects.objects_count,
                                                     label if related_objects.objects_count == 1 else label_plural),
                                      url))
                else:
                    link_list.append(("{} {}".format(related_objects.objects_count,
                                                     related_objects.name),
                                      None))
        return link_list


class TagManager(models.Manager):
    def available_for_meta_business_unit(self, meta_business_unit):
        return self.filter(Q(meta_business_unit=meta_business_unit) | Q(meta_business_unit__isnull=True))

    def used_in_inventory(self):
        query = """
        select tag_id, count(*) from (
            select mt.tag_id, cms.serial_number
            from inventory_machinetag as mt
            join inventory_currentmachinesnapshot as cms on (mt.serial_number = cms.serial_number)

            union

            select mbut.tag_id, cms.serial_number
            from inventory_metabusinessunittag as mbut
            join inventory_businessunit as bu on mbut.meta_business_unit_id = bu.meta_business_unit_id
            join inventory_machinesnapshot as ms on (ms.business_unit_id = bu.id)
            join inventory_currentmachinesnapshot as cms on (cms.machine_snapshot_id = ms.id)
        ) as tag_serial_numbers
        group by tag_id;"""
        cursor = connection.cursor()
        cursor.execute(query)
        counts = {t[0]: t[1] for t in cursor.fetchall()}
        for tag in self.filter(pk__in=counts.keys()):
            yield tag, counts[tag.id]


def validate_color(value):
    if not re.match(r'^[0-9a-fA-F]{6}$', value):
        raise ValidationError(
            _('%(value)s is not a valid color.'),
            params={'value': value},
        )


class Tag(models.Model):
    taxonomy = models.ForeignKey(Taxonomy, on_delete=models.CASCADE, blank=True, null=True)
    meta_business_unit = models.ForeignKey(MetaBusinessUnit, on_delete=models.CASCADE, blank=True, null=True)
    name = models.CharField(max_length=50, unique=True)
    slug = models.SlugField(unique=True, editable=False)
    color = models.CharField(max_length=6,
                             default="0079bf",  # blue from UpdateTagView
                             validators=[validate_color])

    objects = TagManager()

    def __str__(self):
        if self.taxonomy:
            return "{}: {}".format(self.taxonomy, self.name)
        if self.meta_business_unit:
            return "{}/{}".format(self.meta_business_unit, self.name)
        else:
            return self.name

    class Meta:
        ordering = ("meta_business_unit__name", "name")

    def save(self, *args, **kwargs):
        self.slug = slugify(self.name)
        super(Tag, self).save(*args, **kwargs)

    def links(self):
        known_models = {
            EnrollmentSecret: ("enrollment secret", "enrollment secrets", None),
            MachineTag: ("machine", "machines",
                         "{}?tag={}".format(reverse("inventory:index"), self.id)),
            MetaBusinessUnitTag: ("business unit", "business units",
                                  "{}?tag={}".format(reverse("inventory:mbu"), self.id))
        }
        link_list = []
        for related_objects in find_all_related_objects(self):
            if related_objects.name in ("taxonomy", "meta_business_unit"):
                continue
            if related_objects.objects_count:
                if related_objects.to_model in known_models:
                    label, label_plural, url = known_models[related_objects.to_model]
                    link_list.append(("{} {}".format(related_objects.objects_count,
                                                     label if related_objects.objects_count == 1 else label_plural),
                                      url))
                else:
                    link_list.append(("{} {}".format(related_objects.objects_count,
                                                     related_objects.name),
                                      None))
        return link_list


class MachineTag(models.Model):
    serial_number = models.TextField()
    tag = models.ForeignKey(Tag, on_delete=models.CASCADE)

    class Meta:
        unique_together = (('serial_number', 'tag'),)


class MetaBusinessUnitTag(models.Model):
    meta_business_unit = models.ForeignKey(MetaBusinessUnit, on_delete=models.CASCADE)
    tag = models.ForeignKey(Tag, on_delete=models.CASCADE)


class MetaMachine:
    """Simplified access to the ms."""
    def __init__(self, serial_number, snapshots=None):
        self.serial_number = serial_number

    @cached_property
    def _event_serialization_options(self):
        return settings["apps"]["zentral.contrib.inventory"].get("event_serialization", {})

    def _include_groups_in_serialized_info_for_event(self):
        return self._event_serialization_options.get("include_groups", True)

    def _include_principal_user_in_serialized_info_for_event(self):
        return self._event_serialization_options.get("include_principal_user", True)

    @classmethod
    def from_urlsafe_serial_number(cls, urlsafe_serial_number):
        if urlsafe_serial_number.startswith("."):
            urlsafe_serial_number = urlsafe_serial_number[1:].encode("utf-8")
            urlsafe_serial_number += -len(urlsafe_serial_number) % 4 * b"="
            serial_number = base64.urlsafe_b64decode(urlsafe_serial_number).decode("utf-8")
        else:
            serial_number = urlsafe_serial_number
        return cls(serial_number)

    @staticmethod
    def make_urlsafe_serial_number(serial_number):
        if serial_number.startswith(".") or \
           urllib.parse.quote(serial_number, safe="") != serial_number:
            return ".{}".format(
                base64.urlsafe_b64encode(serial_number.encode("utf-8")).decode("utf-8").rstrip("=")
            )
        else:
            return serial_number

    def get_urlsafe_serial_number(self):
        return self.make_urlsafe_serial_number(self.serial_number)

    def get_absolute_url(self):
        return reverse('inventory:machine', args=(self.get_urlsafe_serial_number(),))

    @cached_property
    def snapshots(self):
        return list(MachineSnapshot.objects.current().filter(serial_number=self.serial_number))

    @cached_property
    def computer_name(self):
        for ms in self.snapshots:
            if ms.system_info and ms.system_info.computer_name:
                return ms.system_info.computer_name

    def get_snapshots_sources_for_display(self):
        return sorted((s.source for s in self.snapshots), key=lambda s: s.name)

    def get_url(self):
        try:
            tls_hostname = settings['api']['tls_hostname']
        except KeyError:
            logger.warning("Missing api.tls_hostname configuration key")
        else:
            return "{}{}".format(tls_hostname.rstrip('/'), self.get_absolute_url())

    @property
    def names_with_sources(self):
        names = {}
        for ms in self.snapshots:
            names.setdefault(ms.get_machine_str(), []).append(ms.source.name)
        return names

    # Meta? Business units

    def business_units(self, include_api_enrollment_business_unit=False):
        bu_l = []
        for ms in self.snapshots:
            if (ms.business_unit and
                (include_api_enrollment_business_unit or
                 not ms.business_unit.is_api_enrollment_business_unit())):
                bu_l.append(ms.business_unit)
        return bu_l

    @cached_property
    def meta_business_units(self):
        return set(bu.meta_business_unit for bu in self.business_units(include_api_enrollment_business_unit=True))

    @cached_property
    def meta_business_unit_id_set(self):
        return set(mbu.id for mbu in self.meta_business_units)

    @cached_property
    def platform(self):
        c = Counter(ms.platform for ms in self.snapshots if ms.platform)
        try:
            return c.most_common(1)[0][0]
        except IndexError:
            pass

    @cached_property
    def type(self):
        c = Counter(ms.type for ms in self.snapshots if ms.type)
        try:
            return c.most_common(1)[0][0]
        except IndexError:
            pass

    @cached_property
    def has_deb_packages(self):
        return any(has_deb_packages(ms) for ms in self.snapshots)

    # Filtered snapshots

    def snapshots_with_android_apps(self):
        return list(ms for ms in self.snapshots if ms.android_apps.count())

    def snapshots_with_deb_packages(self):
        return list(ms for ms in self.snapshots if ms.deb_packages.count())

    def snapshots_with_ios_apps(self):
        return list(ms for ms in self.snapshots if ms.ios_apps.count())

    def snapshots_with_osx_app_instances(self):
        return list(ms for ms in self.snapshots if ms.osx_app_instances.count())

    def snapshots_with_profiles(self):
        return list(ms for ms in self.snapshots if ms.profiles.count())

    def snapshots_with_program_instances(self):
        return list(ms for ms in self.snapshots if ms.program_instances.count())

    # Inventory tags

    @cached_property
    def tags_with_types(self):
        tags = [('machine', mt.tag)
                for mt in (MachineTag.objects.select_related('tag',
                                                             'tag__meta_business_unit',
                                                             'tag__taxonomy',
                                                             'tag__taxonomy__meta_business_unit')
                                             .filter(serial_number=self.serial_number))]
        tags.extend(('meta_business_unit', mbut.tag)
                    for mbut in (MetaBusinessUnitTag.objects.select_related('tag',
                                                                            'tag__meta_business_unit',
                                                                            'tag__taxonomy',
                                                                            'tag__taxonomy__meta_business_unit')
                                                            .filter(meta_business_unit__in=self.meta_business_units)))
        tags.sort(key=lambda t: (t[1].meta_business_unit is None, str(t[1]).upper()))
        return tags

    @cached_property
    def tags(self):
        tags = list({t[1] for t in self.tags_with_types})
        tags.sort(key=lambda t: (t.meta_business_unit is None, str(t).upper()))
        return tags

    def available_tags(self):
        # tags w/o mbu or w mbu where this machine is and that this machine does not have yet
        tags = set([])
        for meta_business_unit in self.meta_business_units:
            tags.update(Tag.objects.available_for_meta_business_unit(meta_business_unit))
        tags = list(tags.difference(self.tags))
        tags.sort(key=lambda t: (t.meta_business_unit is None, str(t).upper()))
        return tags

    def tag_names(self):
        # Optimized for only one SQL query
        query = (
            "select name from inventory_tag where id in ("
            "  select tag_id from inventory_machinetag where serial_number = %s"
            "  union"
            "  select tag_id from inventory_metabusinessunittag as mbut"
            "  join inventory_businessunit as bu on (bu.meta_business_unit_id = mbut.meta_business_unit_id)"
            "  join inventory_machinesnapshot as ms on (ms.business_unit_id = bu.id)"
            "  join inventory_currentmachinesnapshot as cms on (cms.machine_snapshot_id = ms.id)"
            "  where cms.serial_number = %s"
            ")"
        )
        cursor = connection.cursor()
        cursor.execute(query, [self.serial_number, self.serial_number])
        return sorted((t[0] for t in cursor.fetchall()), key=lambda n: n.lower())

    def update_taxonomy_tags(self, taxonomy, tag_names):
        tag_names = set(tag_names)
        with transaction.atomic():
            existing_machine_tags = (MachineTag.objects.select_for_update()
                                                       .select_related("tag")
                                                       .filter(serial_number=self.serial_number,
                                                               tag__taxonomy=taxonomy))
            existing_tag_names = set(mt.tag.name for mt in existing_machine_tags)
            # delete old tags
            tag_names_to_delete = existing_tag_names - tag_names
            if tag_names_to_delete:
                existing_machine_tags.filter(tag__name__in=tag_names_to_delete).delete()
            # add missing tags
            for tag_name in tag_names - existing_tag_names:
                try:
                    with transaction.atomic():
                        tag, _ = Tag.objects.get_or_create(taxonomy=taxonomy, name=tag_name)
                except IntegrityError:
                    logger.error("Tag collision, taxonomy '%s', name '%s'", taxonomy.pk, tag_name)
                else:
                    MachineTag.objects.get_or_create(serial_number=self.serial_number, tag=tag)

    def max_incident_severity(self):
        return (MachineIncident.objects.select_related("incident")
                                       .filter(serial_number=self.serial_number, status__in=Status.open_values())
                                       .aggregate(max_incident_severity=Max("incident__severity"))
                )["max_incident_severity"]

    def open_incidents(self):
        return list(MachineIncident.objects.select_related("incident")
                                           .filter(serial_number=self.serial_number, status__in=Status.open_values()))

    def compliance_check_statuses(self):
        return get_machine_compliance_check_statuses(self.serial_number, self.tags)

    def archive(self):
        CurrentMachineSnapshot.objects.filter(serial_number=self.serial_number).delete()

    def has_recent_source_snapshot(self, source_module, max_age=3600):
        query = (
            "select count(*) from inventory_currentmachinesnapshot as cms "
            "join inventory_source as s on (cms.source_id = s.id) "
            "join inventory_machinesnapshotcommit as msc on (cms.machine_snapshot_id=msc.machine_snapshot_id) "
            "where cms.serial_number = %s and s.module = %s and msc.last_seen > %s"
        )
        args = [self.serial_number, source_module, timezone.now() - timedelta(seconds=max_age)]
        with connection.cursor() as cursor:
            cursor.execute(query, args)
            t = cursor.fetchone()
            return t[0] > 0

    # events related methods

    @cached_property
    def _raw_info_for_event(self):
        """Returns all the machine info necessary for the events in 1 DB query.

        This is used in get_probe_filtering_values and get_serialized_info_for_event. Both of them are used during
        the event enrichment pipeline step, thus the use of the single cached property as source.
        """
        query = (
            "with ms as ("
            "  select s.name as src, ms.id, ms.type, ms.platform,"
            "  ms.business_unit_id, ms.os_version_id, ms.system_info_id, ms.principal_user_id"
            "  from inventory_machinesnapshot as ms"
            "  join inventory_currentmachinesnapshot as cms on (cms.machine_snapshot_id = ms.id)"
            "  join inventory_source as s on (ms.source_id = s.id)"
            "  where cms.serial_number = %s"
            "), bu as ("
            "  select s.name as src, s.module, bu.id, bu.key, bu.meta_business_unit_id, bu.name, bu.reference"
            "  from inventory_businessunit as bu"
            "  join ms on (ms.business_unit_id = bu.id)"
            "  join inventory_source as s on (s.id = bu.source_id)"
            "), t as ("
            "  select mt.tag_id as id from inventory_machinetag as mt where mt.serial_number = %s"
            "  union"
            "  select mbut.tag_id as id from inventory_metabusinessunittag as mbut"
            "  join bu on (bu.meta_business_unit_id = mbut.meta_business_unit_id)"
            ") "

            # hostnames
            "select ms.src, 'system_info' as key,"
            "jsonb_build_object('computer_name', si.computer_name, 'hostname', si.hostname) "
            "from inventory_systeminfo as si "
            "join ms on ms.system_info_id = si.id "
            "where si.computer_name is not null or si.hostname is not null "

            "union "

            # business units not API only
            "select bu.src, 'business_unit' as key,"
            "jsonb_build_object('reference', bu.reference, 'name', bu.name, 'key', substring(bu.key, 0, 9)) "
            "from bu "
            "where bu.module <> 'zentral.contrib.inventory'"

            "union "

            # tags
            "select null, 'tags' as key,"
            "jsonb_build_object('id', t.id, 'name', it.name) "
            "from t join inventory_tag as it on (it.id = t.id) "

            "union "

            # os versions
            "select ms.src, 'os_version' as key,"
            "jsonb_build_object("
            "  'name', osv.name, 'major', osv.major, 'minor', osv.minor, 'patch', osv.patch, 'build', osv.build"
            ") "
            "from inventory_osversion as osv join ms on (ms.os_version_id = osv.id) "

            "union "

            # platforms
            "select null, 'platforms' as key,"
            "jsonb_agg(distinct ms.platform) from ms where ms.platform is not null "

            "union "

            # types
            "select null, 'types' as key,"
            "jsonb_agg(distinct ms.type) from ms where ms.type is not null "

            "union "

            # meta business units
            "select null, 'meta_business_units' as key,"
            "jsonb_build_object('id', mbu.id, 'name', mbu.name) "
            "from inventory_metabusinessunit as mbu "
            "join bu on (bu.meta_business_unit_id = mbu.id)"
        )
        if self._include_groups_in_serialized_info_for_event():
            query += (
                "union "

                # groups
                "select ms.src, 'groups' as key, "
                "jsonb_build_object('reference', g.reference, 'name', g.name, 'key', substring(g.key, 0, 9)) "
                "from inventory_machinegroup as g "
                "join inventory_machinesnapshot_groups as msg on (msg.machinegroup_id = g.id) "
                "join ms on (ms.id = msg.machinesnapshot_id) "
            )
        if self._include_principal_user_in_serialized_info_for_event():
            query += (
                "union "

                # principal user
                "select ms.src, 'principal_user' as key,"
                "jsonb_build_object('id', pu.id, 'unique_id', pu.unique_id, 'principal_name', pu.principal_name) "
                "from ms join inventory_principaluser as pu on (ms.principal_user_id = pu.id) "
            )

        cursor = connection.cursor()
        cursor.execute(query, [self.serial_number, self.serial_number])
        return cursor.fetchall()

    def get_probe_filtering_values(self):
        """Returns the values used by the probe inventory filters."""
        platform_fv = None
        type_fv = None
        mbu_ids = set([])
        tag_ids = set([])
        for src, key, agg in self._raw_info_for_event:
            if not agg:
                continue
            if key == "platforms":
                platform_fv = Counter(agg).most_common(1)[0][0]
            elif key == "types":
                type_fv = Counter(agg).most_common(1)[0][0]
            elif key == "meta_business_units":
                mbu_ids.add(agg["id"])
            elif key == "tags":
                tag_ids.add(agg["id"])
        return (platform_fv, type_fv, mbu_ids, tag_ids)

    @cached_property
    def cached_probe_filtering_values(self):
        """Cached version of get_probe_filtering_values"""
        cache_key = "mm-probe-fvs_{}".format(self.get_urlsafe_serial_number())
        filtering_values = cache.get(cache_key)
        if filtering_values is None:
            filtering_values = self.get_probe_filtering_values()
            cache.set(cache_key, filtering_values, 60)  # TODO: Hard coded timeout value
        return filtering_values

    def get_legacy_serialized_info_for_event(self):
        """Serialize the machine information to be included in the events.

        Legacy output. Triggers a lot of DB queries. Kept for reference.
        """
        machine_d = {}
        for ms in self.snapshots:
            source = ms.source
            ms_d = {'name': ms.get_machine_str()}
            if ms.business_unit:
                if not ms.business_unit.is_api_enrollment_business_unit():
                    ms_d['business_unit'] = {'reference': ms.business_unit.reference,
                                             'key': ms.business_unit.get_short_key(),
                                             'name': ms.business_unit.name}
            if ms.os_version:
                ms_d['os_version'] = str(ms.os_version)
            if self._include_groups_in_serialized_info_for_event():
                for group in ms.groups.all():
                    ms_d.setdefault('groups', []).append({'reference': group.reference,
                                                          'key': group.get_short_key(),
                                                          'name': group.name})
            if self._include_principal_user_in_serialized_info_for_event() and ms.principal_user:
                ms_d['principal_user'] = {'id': ms.principal_user.pk,
                                          'unique_id': ms.principal_user.unique_id,
                                          'principal_name': ms.principal_user.principal_name}
            key = slugify(source.name)
            machine_d[key] = ms_d
        for tag in self.tags:
            machine_d.setdefault('tags', []).append({'id': tag.id,
                                                     'name': tag.name})
        for meta_business_unit in self.meta_business_units:
            machine_d.setdefault('meta_business_units', []).append({
                'name': meta_business_unit.name,
                'id': meta_business_unit.id
            })
        if self.platform:
            machine_d['platform'] = self.platform
        if self.type:
            machine_d['type'] = self.type
        return machine_d

    def get_serialized_info_for_event(self):
        """Serialize the machine information to be included in the events.

        Legacy ouput. Only 1 DB query.
        """
        machine_d = {}
        for src, key, agg in self._raw_info_for_event:
            if not agg:
                continue
            if src:
                d = machine_d.setdefault(slugify(src), {})
            else:
                d = machine_d
            if key == "system_info":
                d["name"] = agg["computer_name"] or agg["hostname"]
            elif key == "os_version":
                build = agg.get("build")
                os_version_items = (
                    agg.get("name"),
                    ".".join(str(v) for v in (agg.get(k) for k in ('major', 'minor', 'patch')) if v is not None),
                    f"({build})" if build else None
                )
                os_version_str = " ".join(s for s in os_version_items if s)
                if os_version_str:
                    d[key] = os_version_str
            elif key in ("types", "platforms"):
                d[key[:-1]] = Counter(agg).most_common(1)[0][0]
            elif key == "principal_user":
                d[key] = agg
            else:
                d.setdefault(key, []).append(agg)
        return machine_d

    @cached_property
    def cached_serialized_info_for_event(self):
        """Cached version of get_serialized_info_for_event"""
        cache_key = "mm-si_{}".format(self.get_urlsafe_serial_number())
        serialized_info = cache.get(cache_key)
        if serialized_info is None:
            serialized_info = self.get_serialized_info_for_event()
            cache.set(cache_key, serialized_info, 60)  # TODO: Hard coded timeout value
        return serialized_info


class MACAddressBlockAssignmentOrganization(models.Model):
    name = models.TextField()
    address = models.TextField()

    class Meta:
        unique_together = (('name', 'address'),)


class MACAddressBlockAssignmentManager(models.Manager):
    def import_assignment(self, registry, assignment, organization_name, organization_address):
        organization, _ = MACAddressBlockAssignmentOrganization.objects.get_or_create(name=organization_name,
                                                                                      address=organization_address)
        return MACAddressBlockAssignment.objects.update_or_create(assignment=assignment,
                                                                  defaults={"registry": registry,
                                                                            "organization": organization})


class MACAddressBlockAssignment(models.Model):
    registry = models.CharField(max_length=8,
                                choices=(('MA-L', 'MA-L'),
                                         ('MA-M', 'MA-M'),
                                         ('MA-S', 'MA-S')))
    assignment = models.CharField(max_length=9, unique=True)
    organization = models.ForeignKey(MACAddressBlockAssignmentOrganization, on_delete=models.CASCADE)

    objects = MACAddressBlockAssignmentManager()

    def __str__(self):
        return " ".join((self.registry, self.assignment))


# Enrollment


class EnrollmentSecretManager(models.Manager):
    def verify(self, model, secret,
               user_agent, public_ip_address,
               serial_number=None, udid=None,
               meta_business_unit=None,
               **kwargs):
        kwargs.update({"{}__isnull".format(model): False,
                       "secret": secret})
        qs = self.filter(**kwargs).select_related(model).select_for_update()
        err_msg = None
        if not qs.count():
            raise EnrollmentSecretVerificationFailed("unknown secret")
        else:
            es = qs[0]
            is_valid, err_msg = es.is_valid(serial_number, udid, meta_business_unit)
            if is_valid:
                esr = EnrollmentSecretRequest.objects.create(enrollment_secret=es,
                                                             user_agent=user_agent,
                                                             public_ip_address=public_ip_address,
                                                             serial_number=serial_number,
                                                             udid=udid)
                es.request_count += 1
                es.save()
                return esr
            else:
                raise EnrollmentSecretVerificationFailed(err_msg, es)


class EnrollmentSecret(models.Model):
    secret = models.CharField(max_length=256, unique=True, editable=False)
    meta_business_unit = models.ForeignKey(
        MetaBusinessUnit, on_delete=models.PROTECT,
        help_text="The business unit the machine will be assigned to at enrollment",
    )
    tags = models.ManyToManyField(
        Tag, blank=True,
        help_text="The tags that the machine will get at enrollment"
    )
    serial_numbers = ArrayField(models.TextField(), blank=True, null=True)
    udids = ArrayField(models.TextField(), blank=True, null=True)
    quota = models.IntegerField(null=True, blank=True, validators=[MinValueValidator(1),
                                                                   MaxValueValidator(200000)])
    request_count = models.IntegerField(default=0, validators=[MinValueValidator(0)], editable=False)
    revoked_at = models.DateTimeField(null=True, blank=True)
    expired_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, editable=False)

    objects = EnrollmentSecretManager()

    @property
    def is_revoked(self):
        return self.revoked_at is not None

    @property
    def is_expired(self):
        return bool(self.expired_at and self.expired_at <= timezone.now())

    @property
    def is_used_up(self):
        return bool(self.quota and self.request_count >= self.quota)

    def is_valid(self, serial_number=None, udid=None, meta_business_unit=None):
        err_msg = None
        if self.is_revoked:
            err_msg = "revoked"
        elif self.is_expired:
            err_msg = "expired"
        elif serial_number and self.serial_numbers and serial_number not in self.serial_numbers:
            err_msg = "serial number mismatch"
        elif udid and self.udids and udid not in self.udids:
            err_msg = "udid mismatch"
        elif meta_business_unit and meta_business_unit != self.meta_business_unit:
            err_msg = "business unit mismatch"
        elif self.is_used_up:
            err_msg = "quota used up"
        if err_msg:
            return False, err_msg
        else:
            return True, None

    def save(self, *args, **kwargs):
        if not self.pk:
            self.secret = get_random_string(kwargs.pop("secret_length", 64))
        super().save(*args, **kwargs)

    def serialize_for_event(self):
        d = {}
        for attr in ("pk",
                     "quota", "request_count", "is_used_up",
                     "revoked_at", "is_revoked",
                     "expired_at", "is_expired",
                     "created_at"):
            val = getattr(self, attr)
            if val is not None:
                d[attr] = val
        tags = [{"pk": t.pk, "name": t.name} for t in self.tags.all()]
        if tags:
            d["tags"] = tags
        if self.meta_business_unit:
            d["meta_business_unit"] = self.meta_business_unit.serialize()
        if self.serial_numbers:
            d["serial_numbers"] = self.serial_numbers
        if self.udids:
            d["udids"] = self.udids
        return {"enrollment_secret": d}

    def get_api_enrollment_business_unit(self):
        try:
            return self.meta_business_unit.api_enrollment_business_units()[0]
        except (AttributeError, IndexError):
            pass

    def urlsafe_serial_numbers(self):
        for serial_number in self.serial_numbers:
            yield serial_number, MetaMachine(serial_number).get_urlsafe_serial_number()


class EnrollmentSecretRequest(models.Model):
    enrollment_secret = models.ForeignKey(EnrollmentSecret, on_delete=models.CASCADE)
    user_agent = models.TextField()
    public_ip_address = models.GenericIPAddressField()
    serial_number = models.TextField(null=True, blank=True)
    udid = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)


class BaseEnrollment(models.Model):
    secret = models.OneToOneField(EnrollmentSecret,
                                  on_delete=models.CASCADE,
                                  related_name="%(app_label)s_%(class)s", editable=False)
    version = models.PositiveSmallIntegerField(default=1, editable=False)
    distributor_content_type = models.ForeignKey(ContentType, on_delete=models.PROTECT,
                                                 related_name="+",
                                                 null=True, editable=False)
    distributor_pk = models.PositiveIntegerField(null=True, editable=False)
    distributor = GenericForeignKey("distributor_content_type", "distributor_pk")
    created_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)

    def get_description_for_distributor(self):
        return str(self)

    class Meta:
        abstract = True
        unique_together = (("distributor_content_type", "distributor_pk"),)

    def can_be_deleted(self):
        return not self.distributor

    def can_be_revoked(self):
        return not self.secret.is_revoked

    def save(self, *args, **kwargs):
        if self.pk:
            self.version = F("version") + 1
        super().save(*args, **kwargs)
        if self.distributor:
            self.distributor.enrollment_update_callback()
        self.refresh_from_db()

    def delete(self, *args, **kwargs):
        if self.can_be_deleted():
            self.secret.delete()
            super().delete(*args, **kwargs)
        else:
            raise ValueError("Enrollment {} cannot be deleted".format(self.pk))

    def serialize_for_event(self):
        enrollment_dict = {"pk": self.pk,
                           "created_at": self.created_at}
        enrollment_dict.update(self.secret.serialize_for_event())
        distributor = self.distributor
        if distributor and hasattr(distributor, "serialize_for_event"):
            enrollment_dict.update(distributor.serialize_for_event())
        return enrollment_dict


# Observed files


class FileManager(MTObjectManager):
    def search(self, **kwargs):
        qs = self.all()
        name = kwargs.get("name")
        if name:
            qs = qs.filter(Q(name__icontains=name)
                           | Q(bundle__bundle_id__icontains=name)
                           | Q(bundle__bundle_name__icontains=name))
            return qs.select_related("bundle").order_by("bundle__bundle_name", "name")
        else:
            return []

    def search_certificates(self, **kwargs):
        q = kwargs.get("query")
        if not q:
            return []
        else:
            query = (
                "WITH RECURSIVE certificates AS ("
                "SELECT c1.id, c1.signed_by_id "
                "FROM inventory_certificate AS c1 "
                "JOIN inventory_file invf ON (invf.signed_by_id = c1.id) "

                "UNION "

                "SELECT c2.id, c2.signed_by_id "
                "FROM inventory_certificate AS c2 "
                "JOIN certificates c ON (c.signed_by_id = c2.id)"
                ") SELECT * FROM inventory_certificate c3 "
                "JOIN certificates AS c ON (c.id = c3.id) "
                "WHERE UPPER(c3.common_name) LIKE UPPER(%s) "
                "OR UPPER(c3.organization) LIKE UPPER(%s) "
                "OR UPPER(c3.organizational_unit) LIKE UPPER(%s) "
                "ORDER BY c3.common_name, c3.organization, c3.organizational_unit;"
            )
            q = "%{}%".format(connection.ops.prep_for_like_query(q))
            return Certificate.objects.raw(query, [q, q, q])


class File(AbstractMTObject):
    source = models.ForeignKey(Source, on_delete=models.PROTECT)
    name = models.TextField()
    path = models.TextField()
    sha_256 = models.CharField(max_length=64, db_index=True)
    bundle = models.ForeignKey(OSXApp, on_delete=models.PROTECT, blank=True, null=True)
    bundle_path = models.TextField(blank=True, null=True)
    signed_by = models.ForeignKey(Certificate, on_delete=models.PROTECT, blank=True, null=True)

    objects = FileManager()


# compliance checks


class JMESPathCheck(models.Model):
    compliance_check = models.OneToOneField(
        "compliance_checks.ComplianceCheck",
        on_delete=models.CASCADE,
        related_name="jmespath_check",
        editable=False,
    )
    source_name = models.TextField()
    platforms = ArrayField(
        models.CharField(max_length=32, choices=PLATFORM_CHOICES),
        blank=True,
        default=list,
        help_text="Restrict this check to some platforms"
    )
    tags = models.ManyToManyField(Tag, blank=True)
    jmespath_expression = models.TextField()

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def get_absolute_url(self):
        return reverse("inventory:compliance_check", args=(self.pk,))

    def get_platforms_display(self):
        return ", ".join(sorted(PLATFORM_CHOICES_DICT.get(p) for p in self.platforms))

    def serialize_for_event(self):
        return {
            "pk": self.pk,
            "source_name": self.source_name,
            "tags": sorted(str(tag) for tag in self.tags.select_related("taxonomy", "meta_business_unit").all()),
            "jmespath_expression": self.jmespath_expression,
        }
