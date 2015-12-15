from django.db import models
from zentral.utils.mt_models import AbstractMTObject, MTObjectManager


class BusinessUnit(AbstractMTObject):
    name = models.TextField()
    reference = models.TextField(unique=True)


class MachineGroup(AbstractMTObject):
    business_unit = models.ForeignKey(BusinessUnit, blank=True, null=True)
    name = models.TextField()
    reference = models.TextField(unique=True)


class Machine(AbstractMTObject):
    serial_number = models.TextField(unique=True)


class OSVersion(AbstractMTObject):
    name = models.TextField()
    major = models.PositiveIntegerField()
    minor = models.PositiveIntegerField()
    patch = models.PositiveIntegerField(blank=True, null=True)
    build = models.TextField(blank=True, null=True)


class SystemInfo(AbstractMTObject):
    computer_name = models.TextField()
    hostname = models.TextField(blank=True, null=True)
    hardware_model = models.TextField(blank=True, null=True)
    hardware_serial = models.TextField(blank=True, null=True)
    cpu_type = models.TextField(blank=True, null=True)
    cpu_subtype = models.TextField(blank=True, null=True)
    cpu_brand = models.TextField(blank=True, null=True)
    cpu_physical_cores = models.PositiveIntegerField(blank=True, null=True)
    cpu_logical_cores = models.PositiveIntegerField(blank=True, null=True)
    physical_memory = models.BigIntegerField()


class Certificate(AbstractMTObject):
    common_name = models.TextField()
    organization = models.TextField()
    organizational_unit = models.TextField()
    sha1 = models.CharField(max_length=40)
    sha256 = models.CharField(max_length=64, db_index=True)
    valid_from = models.DateTimeField()
    valid_until = models.DateTimeField()
    signed_by = models.ForeignKey('self', blank=True, null=True)


class OSXApp(AbstractMTObject):
    bundle_id = models.TextField(db_index=True)
    bundle_name = models.TextField(db_index=True)
    version = models.TextField()
    version_str = models.TextField()


class OSXAppInstance(AbstractMTObject):
    app = models.ForeignKey(OSXApp)
    bundle_path = models.TextField()
    path = models.TextField()
    sha1 = models.CharField(max_length=40)
    sha256 = models.CharField(max_length=64, db_index=True)
    type = models.TextField()
    signed_by = models.ForeignKey(Certificate, blank=True, null=True)


class MachineSnapshotManager(MTObjectManager):
    def commit(self, tree):
        obj, created = super().commit(tree)
        if created:
            self.filter(source=obj.source,
                        machine__serial_number=obj.machine.serial_number,
                        next_snapshot__isnull=True).exclude(pk=obj.id).update(next_snapshot=obj)
        return obj, created


class MachineSnapshot(AbstractMTObject):
    source = models.TextField(db_index=True)  # zentral.contrib.munki.postflight
    machine = models.ForeignKey(Machine)
    groups = models.ManyToManyField(MachineGroup)
    os_version = models.ForeignKey(OSVersion, blank=True, null=True)
    system_info = models.ForeignKey(SystemInfo, blank=True, null=True)
    osx_app_instances = models.ManyToManyField(OSXAppInstance)
    next_snapshot = models.ForeignKey('self', blank=True, null=True)

    objects = MachineSnapshotManager()
    mt_excluded_fields = ('next_snapshot',)
