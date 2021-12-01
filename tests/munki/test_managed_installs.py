from datetime import datetime
from django.utils.crypto import get_random_string
from django.test import TestCase
from zentral.contrib.munki.incidents import MunkiFailedInstallIncident, MunkiReinstallIncident
from zentral.contrib.munki.models import Configuration, ManagedInstall
from zentral.contrib.munki.utils import update_managed_install_with_event
from zentral.core.incidents.models import Severity


class MunkiSetupViewsTestCase(TestCase):
    def _force_configuration(self, auto_reinstall_incidents=True, auto_failed_install_incidents=True):
        return Configuration.objects.create(
            name=get_random_string(),
            auto_failed_install_incidents=auto_failed_install_incidents,
            auto_reinstall_incidents=auto_reinstall_incidents,
        )

    def _build_event(self, **kwargs):
        return {
            "type": kwargs.get("type", "install"),
            "name": kwargs.get("name", get_random_string()),
            "display_name": kwargs.get("display_name", get_random_string()),
            "version": kwargs.get("version", get_random_string()),
            "status": 1 if kwargs.get("failed", False) else 0
        }

    def _build_install_event(self, **kwargs):
        kwargs["type"] = "install"
        return self._build_event(**kwargs)

    def _build_removal_event(self, **kwargs):
        kwargs["type"] = "removal"
        return self._build_event(**kwargs)

    def _assert_mi_equal(self, mi_left, mi_right, **new_values):
        for attr in ("pk",
                     "name",
                     "display_name",
                     "installed_version",
                     "installed_at",
                     "failed_version",
                     "failed_at",
                     "reinstall"):
            if attr in new_values:
                mi_right_value = new_values[attr]
            else:
                mi_right_value = getattr(mi_right, attr)
            self.assertEqual(getattr(mi_left, attr), mi_right_value)

    # new - failed install

    def test_new_failed_install_no_incident(self):
        configuration = self._force_configuration(
            auto_failed_install_incidents=False,
            auto_reinstall_incidents=True
        )
        event = self._build_install_event(failed=True)
        event_time = datetime.utcnow()
        serial_number = get_random_string()
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number, name=event["name"])
        self.assertEqual(mi_qs.count(), 0)
        incident_updates = list(update_managed_install_with_event(
            serial_number,
            event,
            event_time,
            configuration
        ))
        self.assertEqual(len(incident_updates), 0)
        self.assertEqual(mi_qs.count(), 1)
        mi = mi_qs.first()
        self.assertEqual(mi.name, event["name"])
        self.assertEqual(mi.display_name, event["display_name"])
        self.assertIsNone(mi.installed_version)
        self.assertIsNone(mi.installed_at)
        self.assertEqual(mi.failed_version, event["version"])
        self.assertEqual(mi.failed_at, event_time)
        self.assertFalse(mi.reinstall)

    def test_new_failed_install_incident(self):
        configuration = self._force_configuration(
            auto_failed_install_incidents=True,
            auto_reinstall_incidents=False
        )
        event = self._build_install_event(failed=True)
        event_time = datetime.utcnow()
        serial_number = get_random_string()
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number, name=event["name"])
        self.assertEqual(mi_qs.count(), 0)
        incident_updates = list(update_managed_install_with_event(
            serial_number,
            event,
            event_time,
            configuration
        ))
        self.assertEqual(len(incident_updates), 1)
        incident_update = incident_updates[0]
        self.assertEqual(incident_update.incident_type, MunkiFailedInstallIncident.incident_type)
        self.assertEqual(incident_update.key, {"munki_pkginfo_name": event["name"],
                                               "munki_pkginfo_version": event["version"]})
        self.assertEqual(incident_update.severity, MunkiFailedInstallIncident.severity)
        self.assertEqual(mi_qs.count(), 1)
        mi = mi_qs.first()
        self.assertEqual(mi.name, event["name"])
        self.assertEqual(mi.display_name, event["display_name"])
        self.assertIsNone(mi.installed_version)
        self.assertIsNone(mi.installed_at)
        self.assertEqual(mi.failed_version, event["version"])
        self.assertEqual(mi.failed_at, event_time)
        self.assertFalse(mi.reinstall)

    # new - successful install

    def test_new_successful_install_no_incident(self):
        configuration = self._force_configuration()
        event = self._build_install_event()
        event_time = datetime.utcnow()
        serial_number = get_random_string()
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number, name=event["name"])
        self.assertEqual(mi_qs.count(), 0)
        incident_updates = list(update_managed_install_with_event(
            serial_number,
            event,
            event_time,
            configuration
        ))
        self.assertEqual(len(incident_updates), 0)
        self.assertEqual(mi_qs.count(), 1)
        mi = mi_qs.first()
        self.assertEqual(mi.name, event["name"])
        self.assertEqual(mi.display_name, event["display_name"])
        self.assertEqual(mi.installed_version, event["version"])
        self.assertEqual(mi.installed_at, event_time)
        self.assertIsNone(mi.failed_version)
        self.assertIsNone(mi.failed_at)
        self.assertFalse(mi.reinstall)

    # new - removal

    def test_new_removal_noop(self):
        configuration = self._force_configuration()
        event = self._build_removal_event()
        event_time = datetime.utcnow()
        serial_number = get_random_string()
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number, name=event["name"])
        self.assertEqual(mi_qs.count(), 0)
        incident_updates = list(update_managed_install_with_event(
            serial_number,
            event,
            event_time,
            configuration
        ))
        self.assertEqual(len(incident_updates), 0)
        self.assertEqual(mi_qs.count(), 0)

    # update - stalled event

    def test_update_removal_more_recent_successful_install_noop(self):
        configuration = self._force_configuration()
        event = self._build_removal_event()
        event_time = datetime(1871, 3, 18)
        serial_number = get_random_string()
        mi = ManagedInstall.objects.create(
            machine_serial_number=serial_number,
            name=event["name"],
            installed_version=event["version"],
            installed_at=datetime.utcnow()
        )
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number, name=event["name"])
        self.assertEqual(mi_qs.count(), 1)
        incident_updates = list(update_managed_install_with_event(
            serial_number,
            event,
            event_time,
            configuration
        ))
        self.assertEqual(len(incident_updates), 0)
        self.assertEqual(mi_qs.count(), 1)
        self._assert_mi_equal(mi_qs.first(), mi)

    def test_update_removal_more_recent_failed_install_noop(self):
        configuration = self._force_configuration()
        event = self._build_removal_event()
        event_time = datetime(1871, 3, 18)
        serial_number = get_random_string()
        mi = ManagedInstall.objects.create(
            machine_serial_number=serial_number,
            name=event["name"],
            failed_version=event["version"],
            failed_at=datetime.utcnow()
        )
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number, name=event["name"])
        self.assertEqual(mi_qs.count(), 1)
        incident_updates = list(update_managed_install_with_event(
            serial_number,
            event,
            event_time,
            configuration
        ))
        self.assertEqual(len(incident_updates), 0)
        self.assertEqual(mi_qs.count(), 1)
        self._assert_mi_equal(mi_qs.first(), mi)

    def test_update_install_more_recent_successful_install_noop(self):
        configuration = self._force_configuration()
        event = self._build_install_event()
        event_time = datetime(1871, 3, 18)
        serial_number = get_random_string()
        mi = ManagedInstall.objects.create(
            machine_serial_number=serial_number,
            name=event["name"],
            installed_version=event["version"],
            installed_at=datetime.utcnow()
        )
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number, name=event["name"])
        self.assertEqual(mi_qs.count(), 1)
        incident_updates = list(update_managed_install_with_event(
            serial_number,
            event,
            event_time,
            configuration
        ))
        self.assertEqual(len(incident_updates), 0)
        self.assertEqual(mi_qs.count(), 1)
        self._assert_mi_equal(mi_qs.first(), mi)

    def test_update_install_more_recent_failed_install_noop(self):
        configuration = self._force_configuration()
        event = self._build_install_event()
        event_time = datetime(1871, 3, 18)
        serial_number = get_random_string()
        mi = ManagedInstall.objects.create(
            machine_serial_number=serial_number,
            name=event["name"],
            failed_version=event["version"],
            failed_at=datetime.utcnow()
        )
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number, name=event["name"])
        self.assertEqual(mi_qs.count(), 1)
        incident_updates = list(update_managed_install_with_event(
            serial_number,
            event,
            event_time,
            configuration
        ))
        self.assertEqual(len(incident_updates), 0)
        self.assertEqual(mi_qs.count(), 1)
        self._assert_mi_equal(mi_qs.first(), mi)

    # update - successful removal

    def test_update_sucessful_removal_no_incident_update(self):
        configuration = self._force_configuration(
            auto_failed_install_incidents=False,
            auto_reinstall_incidents=False
        )
        event = self._build_removal_event()
        event_time = datetime.utcnow()
        serial_number = get_random_string()
        ManagedInstall.objects.create(
            machine_serial_number=serial_number,
            name=event["name"],
            installed_version=event["version"],
            installed_at=datetime(1871, 3, 18),
            failed_version=get_random_string(),
            failed_at=datetime(1871, 3, 18),  # would trigger incident update if auto_failed_install_incidents
            reinstall=True,  # would trigger incident update if auto_reinstall_incidents
        )
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number, name=event["name"])
        self.assertEqual(mi_qs.count(), 1)
        incident_updates = list(update_managed_install_with_event(
            serial_number,
            event,
            event_time,
            configuration
        ))
        self.assertEqual(len(incident_updates), 0)
        self.assertEqual(mi_qs.count(), 0)

    def test_update_sucessful_removal_failed_install_incident_update(self):
        configuration = self._force_configuration(
            auto_failed_install_incidents=True,
            auto_reinstall_incidents=False
        )
        event = self._build_removal_event()
        event_time = datetime.utcnow()
        serial_number = get_random_string()
        failed_version = get_random_string()
        ManagedInstall.objects.create(
            machine_serial_number=serial_number,
            name=event["name"],
            installed_version=event["version"],
            installed_at=datetime(1871, 3, 18),
            failed_version=failed_version,
            failed_at=datetime(1871, 3, 18),  # will trigger incident update
            reinstall=True,  # would trigger incident update if auto_reinstall_incidents
        )
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number, name=event["name"])
        self.assertEqual(mi_qs.count(), 1)
        incident_updates = list(update_managed_install_with_event(
            serial_number,
            event,
            event_time,
            configuration
        ))
        self.assertEqual(len(incident_updates), 1)
        incident_update = incident_updates[0]
        self.assertEqual(incident_update.incident_type, MunkiFailedInstallIncident.incident_type)
        self.assertEqual(incident_update.key, {"munki_pkginfo_name": event["name"],
                                               "munki_pkginfo_version": failed_version})
        self.assertEqual(incident_update.severity, Severity.NONE)
        self.assertEqual(mi_qs.count(), 0)

    def test_update_sucessful_removal_reinstall_incident_update(self):
        configuration = self._force_configuration(
            auto_failed_install_incidents=False,
            auto_reinstall_incidents=True
        )
        event = self._build_removal_event()
        event_time = datetime.utcnow()
        serial_number = get_random_string()
        failed_version = get_random_string()
        ManagedInstall.objects.create(
            machine_serial_number=serial_number,
            name=event["name"],
            installed_version=event["version"],
            installed_at=datetime(1871, 3, 18),
            failed_version=failed_version,
            failed_at=datetime(1871, 3, 18),  # would trigger incident update if auto_failed_install_incidents
            reinstall=True,  # will trigger incident update
        )
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number, name=event["name"])
        self.assertEqual(mi_qs.count(), 1)
        incident_updates = list(update_managed_install_with_event(
            serial_number,
            event,
            event_time,
            configuration
        ))
        self.assertEqual(len(incident_updates), 1)
        incident_update = incident_updates[0]
        self.assertEqual(incident_update.incident_type, MunkiReinstallIncident.incident_type)
        self.assertEqual(incident_update.key, {"munki_pkginfo_name": event["name"],
                                               "munki_pkginfo_version": event["version"]})
        self.assertEqual(incident_update.severity, Severity.NONE)
        self.assertEqual(mi_qs.count(), 0)

    def test_update_sucessful_removal_reinstall_all_incident_updates(self):
        configuration = self._force_configuration()
        event = self._build_removal_event()
        event_time = datetime.utcnow()
        serial_number = get_random_string()
        failed_version = get_random_string()
        ManagedInstall.objects.create(
            machine_serial_number=serial_number,
            name=event["name"],
            installed_version=event["version"],
            installed_at=datetime(1871, 3, 18),
            failed_version=failed_version,
            failed_at=datetime(1871, 3, 18),  # will trigger incident update
            reinstall=True,  # will trigger incident update
        )
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number, name=event["name"])
        self.assertEqual(mi_qs.count(), 1)
        incident_updates = list(update_managed_install_with_event(
            serial_number,
            event,
            event_time,
            configuration
        ))
        self.assertEqual(len(incident_updates), 2)
        failed_install_incident_update = incident_updates[0]
        self.assertEqual(failed_install_incident_update.incident_type, MunkiFailedInstallIncident.incident_type)
        self.assertEqual(failed_install_incident_update.key, {"munki_pkginfo_name": event["name"],
                                                              "munki_pkginfo_version": failed_version})
        self.assertEqual(failed_install_incident_update.severity, Severity.NONE)
        reinstall_incident_update = incident_updates[1]
        self.assertEqual(reinstall_incident_update.incident_type, MunkiReinstallIncident.incident_type)
        self.assertEqual(reinstall_incident_update.key, {"munki_pkginfo_name": event["name"],
                                                         "munki_pkginfo_version": event["version"]})
        self.assertEqual(reinstall_incident_update.severity, Severity.NONE)
        self.assertEqual(mi_qs.count(), 0)

    def test_update_sucessful_removal_reinstall_null_timestamps_no_incidents(self):
        configuration = self._force_configuration()
        event = self._build_removal_event()
        event_time = datetime.utcnow()
        serial_number = get_random_string()
        failed_version = get_random_string()
        ManagedInstall.objects.create(
            machine_serial_number=serial_number,
            name=event["name"],
            installed_version=event["version"],
            installed_at=None,  # block incident update
            failed_version=failed_version,
            failed_at=None,  # block incident update
            reinstall=True,
        )
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number, name=event["name"])
        self.assertEqual(mi_qs.count(), 1)
        incident_updates = list(update_managed_install_with_event(
            serial_number,
            event,
            event_time,
            configuration
        ))
        self.assertEqual(len(incident_updates), 0)
        self.assertEqual(mi_qs.count(), 0)

    # update - failed removal

    def test_update_failed_removal_noop(self):
        configuration = self._force_configuration()
        event = self._build_removal_event(failed=True)
        event_time = datetime.utcnow()
        serial_number = get_random_string()
        mi = ManagedInstall.objects.create(
            machine_serial_number=serial_number,
            name=event["name"],
            installed_version=event["version"],
            installed_at=datetime(1871, 3, 18)
        )
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number, name=event["name"])
        self.assertEqual(mi_qs.count(), 1)
        incident_updates = list(update_managed_install_with_event(
            serial_number,
            event,
            event_time,
            configuration
        ))
        self.assertEqual(len(incident_updates), 0)
        self.assertEqual(mi_qs.count(), 1)
        self._assert_mi_equal(mi_qs.first(), mi)

    # update - failed install

    def test_update_failed_install_stalled_event_noop(self):
        configuration = self._force_configuration()
        event = self._build_removal_event(failed=True)
        event_time = datetime(1871, 3, 18)
        serial_number = get_random_string()
        mi = ManagedInstall.objects.create(
            machine_serial_number=serial_number,
            name=event["name"],
            failed_version=event["version"],
            installed_at=datetime.utcnow()
        )
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number, name=event["name"])
        self.assertEqual(mi_qs.count(), 1)
        incident_updates = list(update_managed_install_with_event(
            serial_number,
            event,
            event_time,
            configuration
        ))
        self.assertEqual(len(incident_updates), 0)
        self.assertEqual(mi_qs.count(), 1)
        self._assert_mi_equal(mi_qs.first(), mi)

    def test_update_failed_install_update_no_incident_update(self):
        configuration = self._force_configuration(
            auto_failed_install_incidents=False,
            auto_reinstall_incidents=True
        )
        event = self._build_install_event(failed=True)
        event_time = datetime.utcnow()
        serial_number = get_random_string()
        mi = ManagedInstall.objects.create(
            machine_serial_number=serial_number,
            name=event["name"],
            installed_version=get_random_string(),
            installed_at=datetime(1871, 3, 18),  # an other version was successfully installed
        )
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number, name=event["name"])
        self.assertEqual(mi_qs.count(), 1)
        incident_updates = list(update_managed_install_with_event(
            serial_number,
            event,
            event_time,
            configuration
        ))
        self.assertEqual(len(incident_updates), 0)
        self.assertEqual(mi_qs.count(), 1)
        self._assert_mi_equal(
            mi_qs.first(), mi,
            display_name=event["display_name"],
            failed_at=event_time,
            failed_version=event["version"],
        )

    def test_update_failed_install_update_one_incident_update(self):
        configuration = self._force_configuration(
            auto_failed_install_incidents=True,
            auto_reinstall_incidents=False
        )
        event = self._build_install_event(failed=True)
        event_time = datetime.utcnow()
        serial_number = get_random_string()
        mi = ManagedInstall.objects.create(
            machine_serial_number=serial_number,
            name=event["name"],
            installed_version=get_random_string(),
            installed_at=datetime(1871, 3, 18),  # an other version was successfully installed
        )
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number, name=event["name"])
        self.assertEqual(mi_qs.count(), 1)
        incident_updates = list(update_managed_install_with_event(
            serial_number,
            event,
            event_time,
            configuration
        ))
        self.assertEqual(len(incident_updates), 1)
        incident_update = incident_updates[0]
        self.assertEqual(incident_update.incident_type, MunkiFailedInstallIncident.incident_type)
        self.assertEqual(incident_update.key, {"munki_pkginfo_name": event["name"],
                                               "munki_pkginfo_version": event["version"]})
        self.assertEqual(incident_update.severity, MunkiFailedInstallIncident.severity)
        self.assertEqual(mi_qs.count(), 1)
        self._assert_mi_equal(
            mi_qs.first(), mi,
            display_name=event["display_name"],
            failed_at=event_time,
            failed_version=event["version"],
        )

    def test_update_failed_install_update_two_incident_updates(self):
        configuration = self._force_configuration(
            auto_failed_install_incidents=True,
            auto_reinstall_incidents=False
        )
        event = self._build_install_event(failed=True)
        event_time = datetime.utcnow()
        serial_number = get_random_string()
        mi = ManagedInstall.objects.create(
            machine_serial_number=serial_number,
            name=event["name"],
            installed_version=get_random_string(),
            installed_at=datetime(1871, 3, 18),  # an other version was successfully installed
            failed_version=get_random_string(),
            failed_at=datetime(1848, 2, 22),  # an other version has previously failed
        )
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number, name=event["name"])
        self.assertEqual(mi_qs.count(), 1)
        incident_updates = list(update_managed_install_with_event(
            serial_number,
            event,
            event_time,
            configuration
        ))
        self.assertEqual(len(incident_updates), 2)
        previous_incident_update = incident_updates[0]
        self.assertEqual(previous_incident_update.incident_type, MunkiFailedInstallIncident.incident_type)
        self.assertEqual(previous_incident_update.key, {"munki_pkginfo_name": event["name"],
                                                        "munki_pkginfo_version": mi.failed_version})
        self.assertEqual(previous_incident_update.severity, Severity.NONE)
        incident_update = incident_updates[1]
        self.assertEqual(incident_update.incident_type, MunkiFailedInstallIncident.incident_type)
        self.assertEqual(incident_update.key, {"munki_pkginfo_name": event["name"],
                                               "munki_pkginfo_version": event["version"]})
        self.assertEqual(incident_update.severity, MunkiFailedInstallIncident.severity)
        self.assertEqual(mi_qs.count(), 1)
        self._assert_mi_equal(
            mi_qs.first(), mi,
            display_name=event["display_name"],
            failed_at=event_time,
            failed_version=event["version"],
        )

    # update - successful install

    def test_update_successful_install_no_installed_at_no_incident(self):
        configuration = self._force_configuration(
            auto_failed_install_incidents=True,
            auto_reinstall_incidents=True
        )
        event = self._build_install_event()
        event_time = datetime.utcnow()
        serial_number = get_random_string()
        mi = ManagedInstall.objects.create(
            machine_serial_number=serial_number,
            name=event["name"],
            installed_version=get_random_string(),
            installed_at=None,  # an other version was successfully installed, without timestamp
        )
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number, name=event["name"])
        self.assertEqual(mi_qs.count(), 1)
        incident_updates = list(update_managed_install_with_event(
            serial_number,
            event,
            event_time,
            configuration
        ))
        self.assertEqual(len(incident_updates), 0)
        self.assertEqual(mi_qs.count(), 1)
        self._assert_mi_equal(
            mi_qs.first(), mi,
            display_name=event["display_name"],
            installed_at=event_time,
            installed_version=event["version"],
        )

    def test_update_successful_install_older_installed_at_no_incident(self):
        configuration = self._force_configuration(
            auto_failed_install_incidents=True,
            auto_reinstall_incidents=True
        )
        event = self._build_install_event()
        event_time = datetime.utcnow()
        serial_number = get_random_string()
        mi = ManagedInstall.objects.create(
            machine_serial_number=serial_number,
            name=event["name"],
            installed_version=get_random_string(),
            installed_at=datetime(1871, 3, 18),  # an other version was successfully installed
        )
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number, name=event["name"])
        self.assertEqual(mi_qs.count(), 1)
        incident_updates = list(update_managed_install_with_event(
            serial_number,
            event,
            event_time,
            configuration
        ))
        self.assertEqual(len(incident_updates), 0)
        self.assertEqual(mi_qs.count(), 1)
        self._assert_mi_equal(
            mi_qs.first(), mi,
            display_name=event["display_name"],
            installed_at=event_time,
            installed_version=event["version"],
        )

    def test_update_successful_install_clear_reinstall_no_incident(self):
        configuration = self._force_configuration(
            auto_failed_install_incidents=True,
            auto_reinstall_incidents=False
        )
        event = self._build_install_event()
        event_time = datetime.utcnow()
        serial_number = get_random_string()
        mi = ManagedInstall.objects.create(
            machine_serial_number=serial_number,
            name=event["name"],
            installed_version=get_random_string(),
            installed_at=datetime(1871, 3, 18),  # an other version was successfully installed
            reinstall=True,  # other installed version was a reinstall
        )
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number, name=event["name"])
        self.assertEqual(mi_qs.count(), 1)
        incident_updates = list(update_managed_install_with_event(
            serial_number,
            event,
            event_time,
            configuration
        ))
        self.assertEqual(len(incident_updates), 0)
        self.assertEqual(mi_qs.count(), 1)
        self._assert_mi_equal(
            mi_qs.first(), mi,
            display_name=event["display_name"],
            installed_at=event_time,
            installed_version=event["version"],
            reinstall=False,  # reinstalled has been cleared by the successful install of the new version
        )

    def test_update_successful_install_clear_reinstall_incident(self):
        configuration = self._force_configuration(
            auto_failed_install_incidents=False,
            auto_reinstall_incidents=True
        )
        event = self._build_install_event()
        event_time = datetime.utcnow()
        serial_number = get_random_string()
        mi = ManagedInstall.objects.create(
            machine_serial_number=serial_number,
            name=event["name"],
            installed_version=get_random_string(),
            installed_at=datetime(1871, 3, 18),  # an other version was successfully installed
            reinstall=True,  # other installed version was a reinstall
        )
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number, name=event["name"])
        self.assertEqual(mi_qs.count(), 1)
        incident_updates = list(update_managed_install_with_event(
            serial_number,
            event,
            event_time,
            configuration
        ))
        self.assertEqual(len(incident_updates), 1)
        incident_update = incident_updates[0]
        self.assertEqual(incident_update.incident_type, MunkiReinstallIncident.incident_type)
        self.assertEqual(incident_update.key, {"munki_pkginfo_name": event["name"],
                                               "munki_pkginfo_version": mi.installed_version})
        self.assertEqual(incident_update.severity, Severity.NONE)
        self.assertEqual(mi_qs.count(), 1)
        self._assert_mi_equal(
            mi_qs.first(), mi,
            display_name=event["display_name"],
            installed_at=event_time,
            installed_version=event["version"],
            reinstall=False,  # reinstalled has been cleared by the successful install of the new version
        )

    def test_update_successful_install_set_reinstall_no_incident(self):
        configuration = self._force_configuration(
            auto_failed_install_incidents=True,
            auto_reinstall_incidents=False
        )
        event = self._build_install_event()
        event_time = datetime.utcnow()
        serial_number = get_random_string()
        mi = ManagedInstall.objects.create(
            machine_serial_number=serial_number,
            name=event["name"],
            installed_version=event["version"],
            installed_at=datetime(1871, 3, 18),  # version was successfully installed
            reinstall=False,  # version was not a reinstall
        )
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number, name=event["name"])
        self.assertEqual(mi_qs.count(), 1)
        incident_updates = list(update_managed_install_with_event(
            serial_number,
            event,
            event_time,
            configuration
        ))
        self.assertEqual(len(incident_updates), 0)
        self.assertEqual(mi_qs.count(), 1)
        self._assert_mi_equal(
            mi_qs.first(), mi,
            display_name=event["display_name"],
            installed_at=event_time,
            reinstall=True,  # reinstalled has been set by the successful install of the same version
        )

    def test_update_successful_install_set_reinstall_incident(self):
        configuration = self._force_configuration(
            auto_failed_install_incidents=False,
            auto_reinstall_incidents=True
        )
        event = self._build_install_event()
        event_time = datetime.utcnow()
        serial_number = get_random_string()
        mi = ManagedInstall.objects.create(
            machine_serial_number=serial_number,
            name=event["name"],
            installed_version=event["version"],
            installed_at=datetime(1871, 3, 18),  # version was successfully installed
            reinstall=False,  # version was not a reinstall
        )
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number, name=event["name"])
        self.assertEqual(mi_qs.count(), 1)
        incident_updates = list(update_managed_install_with_event(
            serial_number,
            event,
            event_time,
            configuration
        ))
        self.assertEqual(len(incident_updates), 1)
        incident_update = incident_updates[0]
        self.assertEqual(incident_update.incident_type, MunkiReinstallIncident.incident_type)
        self.assertEqual(incident_update.key, {"munki_pkginfo_name": event["name"],
                                               "munki_pkginfo_version": event["version"]})
        self.assertEqual(incident_update.severity, MunkiReinstallIncident.severity)
        self.assertEqual(mi_qs.count(), 1)
        self._assert_mi_equal(
            mi_qs.first(), mi,
            display_name=event["display_name"],
            installed_at=event_time,
            reinstall=True,  # reinstalled has been set by the successful install of the same version
        )

    def test_update_successful_install_reinstall_already_set_no_incident(self):
        configuration = self._force_configuration(
            auto_failed_install_incidents=False,
            auto_reinstall_incidents=True
        )
        event = self._build_install_event()
        event_time = datetime.utcnow()
        serial_number = get_random_string()
        mi = ManagedInstall.objects.create(
            machine_serial_number=serial_number,
            name=event["name"],
            installed_version=event["version"],
            installed_at=datetime(1871, 3, 18),  # version was successfully installed
            reinstall=True,  # version was already a reinstall
        )
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number, name=event["name"])
        self.assertEqual(mi_qs.count(), 1)
        incident_updates = list(update_managed_install_with_event(
            serial_number,
            event,
            event_time,
            configuration
        ))
        self.assertEqual(len(incident_updates), 0)
        self.assertEqual(mi_qs.count(), 1)
        self._assert_mi_equal(
            mi_qs.first(), mi,
            display_name=event["display_name"],
            installed_at=event_time,
        )

    def test_update_successful_install_clear_previously_failed_no_incident(self):
        configuration = self._force_configuration(
            auto_failed_install_incidents=False,
            auto_reinstall_incidents=True
        )
        event = self._build_install_event()
        event_time = datetime.utcnow()
        serial_number = get_random_string()
        mi = ManagedInstall.objects.create(
            machine_serial_number=serial_number,
            name=event["name"],
            failed_version=get_random_string(),  # previously failed version
            failed_at=datetime(1871, 3, 18),
        )
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number, name=event["name"])
        self.assertEqual(mi_qs.count(), 1)
        incident_updates = list(update_managed_install_with_event(
            serial_number,
            event,
            event_time,
            configuration
        ))
        self.assertEqual(len(incident_updates), 0)  # because of the configuration
        self.assertEqual(mi_qs.count(), 1)
        self._assert_mi_equal(
            mi_qs.first(), mi,
            display_name=event["display_name"],
            installed_version=event["version"],
            installed_at=event_time,
            failed_version=None,
            failed_at=None,
        )

    def test_update_successful_install_clear_previously_failed_clear_previous_failed_incident(self):
        configuration = self._force_configuration(
            auto_failed_install_incidents=True,
            auto_reinstall_incidents=False
        )
        event = self._build_install_event()
        event_time = datetime.utcnow()
        serial_number = get_random_string()
        mi = ManagedInstall.objects.create(
            machine_serial_number=serial_number,
            name=event["name"],
            failed_version=get_random_string(),  # previously failed version
            failed_at=datetime(1871, 3, 18),
        )
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number, name=event["name"])
        self.assertEqual(mi_qs.count(), 1)
        incident_updates = list(update_managed_install_with_event(
            serial_number,
            event,
            event_time,
            configuration
        ))
        self.assertEqual(len(incident_updates), 1)
        incident_update = incident_updates[0]
        self.assertEqual(incident_update.incident_type, MunkiFailedInstallIncident.incident_type)
        self.assertEqual(incident_update.key, {"munki_pkginfo_name": event["name"],
                                               "munki_pkginfo_version": mi.failed_version})
        self.assertEqual(incident_update.severity, Severity.NONE)
        self.assertEqual(mi_qs.count(), 1)
        self._assert_mi_equal(
            mi_qs.first(), mi,
            display_name=event["display_name"],
            installed_version=event["version"],
            installed_at=event_time,
            failed_version=None,
            failed_at=None,
        )

    def test_update_successful_install_clear_two_incident_updates(self):
        configuration = self._force_configuration(
            auto_failed_install_incidents=True,
            auto_reinstall_incidents=True,
        )
        event = self._build_install_event()
        event_time = datetime.utcnow()
        serial_number = get_random_string()
        mi = ManagedInstall.objects.create(
            machine_serial_number=serial_number,
            name=event["name"],
            installed_version=event["version"],  # same version, will trigger a reinstall incident
            installed_at=datetime(1871, 3, 18),
            failed_version=get_random_string(),  # previously failed version, will be cleared
            failed_at=datetime(1871, 3, 18),
        )
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number, name=event["name"])
        self.assertEqual(mi_qs.count(), 1)
        incident_updates = list(update_managed_install_with_event(
            serial_number,
            event,
            event_time,
            configuration
        ))
        self.assertEqual(len(incident_updates), 2)
        reinstall_incident_update = incident_updates[0]
        self.assertEqual(reinstall_incident_update.incident_type, MunkiReinstallIncident.incident_type)
        self.assertEqual(reinstall_incident_update.key, {"munki_pkginfo_name": event["name"],
                                                         "munki_pkginfo_version": event["version"]})
        self.assertEqual(reinstall_incident_update.severity, MunkiReinstallIncident.severity)
        failed_install_incident_update = incident_updates[1]
        self.assertEqual(failed_install_incident_update.incident_type, MunkiFailedInstallIncident.incident_type)
        self.assertEqual(failed_install_incident_update.key, {"munki_pkginfo_name": event["name"],
                                                              "munki_pkginfo_version": mi.failed_version})
        self.assertEqual(failed_install_incident_update.severity, Severity.NONE)
        self.assertEqual(mi_qs.count(), 1)
        self._assert_mi_equal(
            mi_qs.first(), mi,
            display_name=event["display_name"],
            installed_at=event_time,
            failed_version=None,
            failed_at=None,
            reinstall=True,  # set during the update
        )
