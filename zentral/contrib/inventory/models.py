from collections import Counter
import colorsys
from datetime import datetime, timedelta
import logging
import re
from django.contrib.postgres.fields import JSONField
from django.core.exceptions import ValidationError
from django.core.urlresolvers import reverse
from django.db import connection, IntegrityError, models, transaction
from django.db.models import Count, Q
from django.utils.functional import cached_property
from django.utils.text import slugify
from django.utils.timezone import is_aware, make_naive
from django.utils.translation import ugettext_lazy as _
from zentral.conf import settings
from zentral.utils.mt_models import AbstractMTObject, prepare_commit_tree, MTObjectManager, MTOError
from .conf import (has_deb_packages,
                   update_ms_tree_platform, update_ms_tree_type,
                   PLATFORM_CHOICES, PLATFORM_CHOICES_DICT,
                   TYPE_CHOICES, TYPE_CHOICES_DICT)

logger = logging.getLogger('zentral.contrib.inventory.models')


class MetaBusinessUnitManager(models.Manager):
    def get_or_create_with_bu_key_and_name(self, key, name):
        try:
            mbu = self.get(businessunit__key=key)
        except MetaBusinessUnit.DoesNotExist:
            mbu = MetaBusinessUnit(name=name)
            mbu.save()
        return mbu

    def available_for_api_enrollment(self):
        return self.filter(businessunit__source__module='zentral.contrib.inventory')


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


class Link(AbstractMTObject):
    anchor_text = models.TextField()
    url = models.URLField()


class AbstractMachineGroupManager(MTObjectManager):
    def current(self):
        return (self.filter(machinesnapshot__currentmachinesnapshot__isnull=False)
                    .distinct()
                    .select_related('source')
                    .order_by('source__module', 'name'))


class AbstractMachineGroup(AbstractMTObject):
    source = models.ForeignKey(Source)
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
    meta_business_unit = models.ForeignKey(MetaBusinessUnit)
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


class MachineGroup(AbstractMachineGroup):
    machine_links = models.ManyToManyField(Link, related_name="+")  # tmpl for links to machine in a group


class OSVersion(AbstractMTObject):
    name = models.TextField(blank=True, null=True)
    major = models.PositiveIntegerField()
    minor = models.PositiveIntegerField(blank=True, null=True)
    patch = models.PositiveIntegerField(blank=True, null=True)
    build = models.TextField(blank=True, null=True)

    def __str__(self):
        l = [".".join((str(i) for i in (self.major, self.minor, self.patch) if i is not None))]
        if self.name:
            l.insert(0, self.name)
        if self.build:
            l.append("({})".format(self.build))
        return " ".join(l)


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


class NetworkInterface(AbstractMTObject):
    interface = models.TextField(blank=False, null=False)
    mac = models.CharField(max_length=23, blank=False, null=False)  # 48 or 64 bit with separators
    address = models.GenericIPAddressField(blank=False, null=False, unpack_ipv4=True)
    mask = models.GenericIPAddressField(blank=True, null=True, unpack_ipv4=True)
    broadcast = models.GenericIPAddressField(blank=True, null=True, unpack_ipv4=True)

    class Meta:
        ordering = ('interface',)

    def get_mac_organization(self):
        mac = self.mac.replace(":", "").upper()
        assignments = [mac[:l] for l in (9, 7, 6)]
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
    bundle_version = models.TextField(blank=True, null=True)
    bundle_version_str = models.TextField(blank=True, null=True)

    objects = OSXAppManager()

    def __str__(self):
        return " ".join(s for s in (self.bundle_name, self.bundle_version_str) if s)

    def sources(self):
        return (Source.objects.distinct()
                .filter(machinesnapshot__osx_app_instances__app=self)
                .order_by('module', 'name'))

    def get_sources_for_display(self):
        return " ".join(s.name for s in self.sources())

    def current_instances(self):
        return (self.osxappinstance_set.filter(machinesnapshot__currentmachinesnapshot__isnull=False)
                                       .annotate(machinesnapshot_num=Count('machinesnapshot')))


class Certificate(AbstractMTObject):
    common_name = models.TextField(blank=True, null=True)
    organization = models.TextField(blank=True, null=True)
    organizational_unit = models.TextField(blank=True, null=True)
    sha_1 = models.CharField(max_length=40, blank=True, null=True)
    sha_256 = models.CharField(max_length=64, db_index=True)
    valid_from = models.DateTimeField()
    valid_until = models.DateTimeField()
    signed_by = models.ForeignKey('self', blank=True, null=True)


class OSXAppInstance(AbstractMTObject):
    app = models.ForeignKey(OSXApp)
    bundle_path = models.TextField(blank=True, null=True)
    path = models.TextField(blank=True, null=True)
    sha_1 = models.CharField(max_length=40, blank=True, null=True)
    sha_256 = models.CharField(max_length=64, db_index=True, blank=True, null=True)
    type = models.TextField(blank=True, null=True)
    signed_by = models.ForeignKey(Certificate, blank=True, null=True)

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
    trusted_facts = models.ForeignKey(PuppetTrustedFacts, blank=True, null=True)
    core_facts = models.ForeignKey(PuppetCoreFacts, blank=True, null=True)
    extra_facts = JSONField(blank=True, null=True)


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
    source = models.ForeignKey(Source)
    reference = models.TextField(blank=True, null=True)
    serial_number = models.TextField(db_index=True)
    links = models.ManyToManyField(Link)
    business_unit = models.ForeignKey(BusinessUnit, blank=True, null=True)
    groups = models.ManyToManyField(MachineGroup)
    os_version = models.ForeignKey(OSVersion, blank=True, null=True)
    platform = models.CharField(max_length=32, blank=True, null=True, choices=PLATFORM_CHOICES)
    system_info = models.ForeignKey(SystemInfo, blank=True, null=True)
    type = models.CharField(max_length=32, blank=True, null=True, choices=TYPE_CHOICES)
    network_interfaces = models.ManyToManyField(NetworkInterface)
    osx_app_instances = models.ManyToManyField(OSXAppInstance)
    deb_packages = models.ManyToManyField(DebPackage)
    teamviewer = models.ForeignKey(TeamViewer, blank=True, null=True)
    puppet_node = models.ForeignKey(PuppetNode, blank=True, null=True)
    public_ip_address = models.GenericIPAddressField(blank=True, null=True, unpack_ipv4=True)

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

    def ordered_osx_app_instances(self):
        return self.osx_app_instances.select_related('app').all().order_by('app__bundle_name',
                                                                           'app__bundle_version_str',
                                                                           'bundle_path')

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
        if is_aware(last_seen):
            last_seen = make_naive(last_seen)
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
                                                                defaults={'machine_snapshot': machine_snapshot})
                return new_msc, machine_snapshot
        except IntegrityError:
            msc = MachineSnapshotCommit.objects.get(serial_number=serial_number,
                                                    source=source,
                                                    version=new_version)
            if msc.machine_snapshot == machine_snapshot:
                logger.warning("MachineSnapshotCommit race with same snapshot for "
                               "source {} and serial_number {}".format(source, serial_number))
                return None, machine_snapshot
            else:
                raise MTOError("MachineSnapshotCommit race for "
                               "source {} and serial_number {}".format(source, serial_number))


class MachineSnapshotCommit(models.Model):
    serial_number = models.TextField(db_index=True)
    source = models.ForeignKey(Source)
    version = models.PositiveIntegerField(default=1)
    machine_snapshot = models.ForeignKey(MachineSnapshot)
    parent = models.ForeignKey('self', blank=True, null=True)
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
    source = models.ForeignKey(Source)
    machine_snapshot = models.ForeignKey(MachineSnapshot)

    class Meta:
        unique_together = ('serial_number', 'source')


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
    meta_business_unit = models.ForeignKey(MetaBusinessUnit, blank=True, null=True)
    name = models.CharField(max_length=50, unique=True)
    slug = models.SlugField(unique=True)
    color = models.CharField(max_length=6,
                             default="0079bf",  # blue from UpdateTagView
                             validators=[validate_color])

    objects = TagManager()

    def __str__(self):
        if self.meta_business_unit:
            return "{}/{}".format(self.meta_business_unit, self.name)
        else:
            return self.name

    class Meta:
        ordering = ("meta_business_unit__name", "name")

    def save(self, *args, **kwargs):
        self.slug = slugify(self.name)
        super(Tag, self).save(*args, **kwargs)

    def text_color(self):
        try:
            hls = colorsys.rgb_to_hls(float(int(self.color[0:2], 16))/255.0,
                                      float(int(self.color[2:4], 16))/255.0,
                                      float(int(self.color[4:6], 16))/255.0,)
        except ValueError:
            return "000"
        else:
            if hls[1] > .7:
                return "000"
            else:
                return "FFF"

    def need_border(self):
        return self.color.upper() in ['FFFFFF', 'FFF']

    def links(self):
        l = []
        for model, label, attribute, base_url in ((MachineTag,
                                                   "machines", "tag",
                                                   reverse("inventory:index")),
                                                  (MetaBusinessUnitTag,
                                                   "business units", "tag",
                                                   reverse("inventory:mbu"))):
            obj_count = model.objects.filter(**{attribute: self.id}).count()
            if obj_count:
                l.append(("{} {}".format(obj_count, label),
                          "{}?tag={}".format(base_url, self.id)))
        return l


class MachineTag(models.Model):
    serial_number = models.TextField()
    tag = models.ForeignKey(Tag, on_delete=models.CASCADE)

    class Meta:
        unique_together = (('serial_number', 'tag'),)


class MetaBusinessUnitTag(models.Model):
    meta_business_unit = models.ForeignKey(MetaBusinessUnit)
    tag = models.ForeignKey(Tag, on_delete=models.CASCADE)


class MetaMachine(object):
    """Simplified access to the ms."""
    def __init__(self, serial_number, snapshots=None):
        self.serial_number = serial_number

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
            return "{}{}".format(tls_hostname.rstrip('/'),
                                 reverse('inventory:machine',
                                         args=(self.serial_number,)))

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

    def snapshots_with_osx_app_instances(self):
        return list(ms for ms in self.snapshots if ms.osx_app_instances.count())

    # Inventory tags

    @cached_property
    def tags_with_types(self):
        tags = [('machine', mt.tag)
                for mt in MachineTag.objects.select_related('tag').filter(
                    serial_number=self.serial_number
                )]
        tags.extend(('meta_business_unit', mbut.tag)
                    for mbut in MetaBusinessUnitTag.objects.filter(meta_business_unit__in=self.meta_business_units))
        tags.sort(key=lambda t: (t[1].meta_business_unit is None, str(t[1]).upper()))
        return tags

    @cached_property
    def tags(self):
        tags = list({t[1] for t in self.tags_with_types})
        tags.sort(key=lambda t: (t.meta_business_unit is None, str(t).upper()))
        return tags

    @cached_property
    def tag_id_set(self):
        return set(t.id for t in self.tags)

    def available_tags(self):
        # tags w/o mbu or w mbu where this machine is and that this machine does not have yet
        tags = set([])
        for meta_business_unit in self.meta_business_units:
            tags.update(Tag.objects.available_for_meta_business_unit(meta_business_unit))
        tags = list(tags.difference(self.tags))
        tags.sort(key=lambda t: (t.meta_business_unit is None, str(t).upper()))
        return tags

    def archive(self):
        CurrentMachineSnapshot.objects.filter(serial_number=self.serial_number).delete()


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
    organization = models.ForeignKey(MACAddressBlockAssignmentOrganization)

    objects = MACAddressBlockAssignmentManager()

    def __str__(self):
        return " ".join((self.registry, self.assignment))
