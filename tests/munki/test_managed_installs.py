from datetime import datetime
from django.utils.crypto import get_random_string
from django.test import TestCase
from zentral.contrib.munki.incidents import MunkiFailedInstallIncident, MunkiReinstallIncident
from zentral.contrib.munki.models import Configuration, ManagedInstall
from zentral.contrib.munki.utils import apply_managed_installs, update_managed_install_with_event
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
        debug = new_values.pop("debug", False)
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
            if debug:
                print("==?", getattr(mi_left, attr), mi_right_value)
            self.assertEqual(getattr(mi_left, attr), mi_right_value)
        if debug:
            input("?")

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

    # apply_managed_installs

    def test_a_m_i_one_install_no_existing_mi_no_incident_updates(self):
        configuration = self._force_configuration(
            auto_failed_install_incidents=True,
            auto_reinstall_incidents=True,
        )

        # reported intall
        serial_number = get_random_string()
        name = get_random_string()
        version = get_random_string()
        display_name = None
        installed_at = "2019-12-03T09:49:11+00:00"

        # no existing mi
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number, name=name)
        self.assertEqual(mi_qs.count(), 0)

        # do apply
        incident_updates = list(apply_managed_installs(
            serial_number,
            [(name, version, display_name, installed_at)],
            configuration
        ))

        # no incident updates
        self.assertEqual(len(incident_updates), 0)

        # new mi
        self.assertEqual(mi_qs.count(), 1)
        mi = mi_qs.first()
        self.assertEqual(mi.name, name)
        self.assertEqual(mi.display_name, name)  # display name is None, so name is used instead
        self.assertEqual(mi.installed_at, datetime(2019, 12, 3, 9, 49, 11))
        self.assertEqual(mi.installed_version, version)
        self.assertIsNone(mi.failed_at)
        self.assertIsNone(mi.failed_version)
        self.assertFalse(mi.reinstall)

    def test_a_m_i_one_install_existing_mi_installed_at_null_no_update_no_incident_updates(self):
        configuration = self._force_configuration(
            auto_failed_install_incidents=True,
            auto_reinstall_incidents=True,
        )

        # reported install
        serial_number = get_random_string()
        name = get_random_string()
        version = get_random_string()
        display_name = None
        installed_at = None  # None here prevent the update

        # existing mi
        mi = ManagedInstall.objects.create(
            machine_serial_number=serial_number,
            name=name,
            display_name=get_random_string(),
            installed_version=get_random_string(),
            installed_at=datetime(1871, 3, 18),
            failed_version=None,
            failed_at=None,
        )
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number, name=name)
        self.assertEqual(mi_qs.count(), 1)

        # do apply
        incident_updates = list(apply_managed_installs(
            serial_number,
            [(name, version, display_name, installed_at)],
            configuration
        ))

        # no incident updates
        self.assertEqual(len(incident_updates), 0)

        # existing mi not updated
        self.assertEqual(mi_qs.count(), 1)
        self._assert_mi_equal(mi_qs.first(), mi)

    def test_a_m_i_one_install_existing_mi_installed_at_older_no_update_no_incident_updates(self):
        configuration = self._force_configuration(
            auto_failed_install_incidents=True,
            auto_reinstall_incidents=True,
        )

        # reported install
        serial_number = get_random_string()
        name = get_random_string()
        version = get_random_string()
        display_name = None
        installed_at = datetime(1871, 3, 18)  # older than the existing one. no update

        # existing mi
        mi = ManagedInstall.objects.create(
            machine_serial_number=serial_number,
            name=name,
            display_name=get_random_string(),
            installed_version=get_random_string(),
            installed_at=datetime.utcnow(),
            failed_version=None,
            failed_at=None,
        )
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number, name=name)
        self.assertEqual(mi_qs.count(), 1)

        # do apply
        incident_updates = list(apply_managed_installs(
            serial_number,
            [(name, version, display_name, installed_at)],
            configuration
        ))

        # no incident updates
        self.assertEqual(len(incident_updates), 0)

        # existing mi not updated
        self.assertEqual(mi_qs.count(), 1)
        self._assert_mi_equal(mi_qs.first(), mi)

    def test_a_m_i_one_install_existing_mi_update_no_incident_updates(self):
        configuration = self._force_configuration(
            auto_failed_install_incidents=True,
            auto_reinstall_incidents=True,
        )

        # reported install
        serial_number = get_random_string()
        name = get_random_string()
        version = get_random_string()
        display_name = get_random_string()
        installed_at = datetime.utcnow()

        # existing mi
        mi = ManagedInstall.objects.create(
            machine_serial_number=serial_number,
            name=name,
            display_name=get_random_string(),
            installed_version=get_random_string(),
            installed_at=datetime(1871, 3, 18),
            failed_version=None,
            failed_at=None,
        )
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number, name=name)
        self.assertEqual(mi_qs.count(), 1)

        # do apply
        incident_updates = list(apply_managed_installs(
            serial_number,
            [(name, version, display_name, installed_at)],
            configuration
        ))

        # no incident updates
        self.assertEqual(len(incident_updates), 0)

        # existing mi updated
        self.assertEqual(mi_qs.count(), 1)
        self._assert_mi_equal(
            mi_qs.first(), mi,
            display_name=display_name,
            installed_version=version,
            installed_at=installed_at,
        )

    def test_a_m_i_one_install_existing_clear_failed_install_mi_update_no_incident_updates(self):
        configuration = self._force_configuration(
            auto_failed_install_incidents=False,  # blocks the incident update
            auto_reinstall_incidents=True,
        )

        # reported install
        serial_number = get_random_string()
        name = get_random_string()
        version = get_random_string()
        display_name = get_random_string()
        installed_at = datetime.utcnow()

        # existing mi, with failed install
        mi = ManagedInstall.objects.create(
            machine_serial_number=serial_number,
            name=name,
            display_name=get_random_string(),
            installed_version=get_random_string(),
            installed_at=datetime(1871, 3, 18),
            failed_version=get_random_string(),
            failed_at=datetime(1968, 5, 13),
        )
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number, name=name)
        self.assertEqual(mi_qs.count(), 1)

        # do apply
        incident_updates = list(apply_managed_installs(
            serial_number,
            [(name, version, display_name, installed_at)],
            configuration
        ))

        # no incident updates
        self.assertEqual(len(incident_updates), 0)

        # existing mi updated
        self.assertEqual(mi_qs.count(), 1)
        self._assert_mi_equal(
            mi_qs.first(), mi,
            display_name=display_name,
            installed_version=version,
            installed_at=installed_at,
            failed_version=None,  # cleared
            failed_at=None,  # cleared
        )

    def test_a_m_i_one_install_existing_clear_failed_install_mi_update_one_incident_updates(self):
        configuration = self._force_configuration(
            auto_failed_install_incidents=True,
            auto_reinstall_incidents=True,
        )

        # reported install
        serial_number = get_random_string()
        name = get_random_string()
        version = get_random_string()
        display_name = get_random_string()
        installed_at = datetime.utcnow()

        # existing mi, with failed install
        mi = ManagedInstall.objects.create(
            machine_serial_number=serial_number,
            name=name,
            display_name=get_random_string(),
            installed_version=get_random_string(),
            installed_at=datetime(1871, 3, 18),
            failed_version=get_random_string(),
            failed_at=datetime(1968, 5, 13),
        )
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number, name=name)
        self.assertEqual(mi_qs.count(), 1)

        # do apply
        incident_updates = list(apply_managed_installs(
            serial_number,
            [(name, version, display_name, installed_at)],
            configuration
        ))

        # one incident updates
        self.assertEqual(len(incident_updates), 1)
        incident_update = incident_updates[0]
        self.assertEqual(incident_update.incident_type, MunkiFailedInstallIncident.incident_type)
        self.assertEqual(incident_update.key, {"munki_pkginfo_name": name,
                                               "munki_pkginfo_version": mi.failed_version})
        self.assertEqual(incident_update.severity, Severity.NONE)

        # existing mi updated
        self.assertEqual(mi_qs.count(), 1)
        self._assert_mi_equal(
            mi_qs.first(), mi,
            display_name=display_name,
            installed_version=version,
            installed_at=installed_at,
            failed_version=None,  # cleared
            failed_at=None,  # cleared
        )

    def test_a_m_i_reinstall_mi_update_no_incident_updates(self):
        configuration = self._force_configuration(
            auto_failed_install_incidents=True,
            auto_reinstall_incidents=False,  # blocks the incident update
        )

        # reported install
        serial_number = get_random_string()
        name = get_random_string()
        version = get_random_string()
        display_name = get_random_string()
        installed_at = datetime.utcnow()

        # existing mi, with failed install
        mi = ManagedInstall.objects.create(
            machine_serial_number=serial_number,
            name=name,
            display_name=get_random_string(),
            installed_version=version,
            installed_at=datetime(1871, 3, 18),
            failed_version=None,
            failed_at=None,
        )
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number, name=name)
        self.assertEqual(mi_qs.count(), 1)

        # do apply
        incident_updates = list(apply_managed_installs(
            serial_number,
            [(name, version, display_name, installed_at)],
            configuration
        ))

        # no incident updates
        self.assertEqual(len(incident_updates), 0)

        # existing mi updated
        self.assertEqual(mi_qs.count(), 1)
        self._assert_mi_equal(
            mi_qs.first(), mi,
            display_name=display_name,
            installed_at=installed_at,
            reinstall=True,
        )

    def test_a_m_i_reinstall_on_reinstall_mi_update_no_incident_updates(self):
        configuration = self._force_configuration(
            auto_failed_install_incidents=True,
            auto_reinstall_incidents=True,
        )

        # reported install
        serial_number = get_random_string()
        name = get_random_string()
        version = get_random_string()
        display_name = get_random_string()
        installed_at = datetime.utcnow()

        # existing mi, with failed install
        mi = ManagedInstall.objects.create(
            machine_serial_number=serial_number,
            name=name,
            display_name=get_random_string(),
            installed_version=version,
            installed_at=datetime(1871, 3, 18),
            failed_version=None,
            failed_at=None,
            reinstall=True,  # already a reinstall, no incident update
        )
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number, name=name)
        self.assertEqual(mi_qs.count(), 1)

        # do apply
        incident_updates = list(apply_managed_installs(
            serial_number,
            [(name, version, display_name, installed_at)],
            configuration
        ))

        # no incident updates
        self.assertEqual(len(incident_updates), 0)

        # existing mi updated
        self.assertEqual(mi_qs.count(), 1)
        self._assert_mi_equal(
            mi_qs.first(), mi,
            display_name=display_name,
            installed_at=installed_at,
        )

    def test_a_m_i_reinstall_mi_update_reinstall_incident_updates(self):
        configuration = self._force_configuration(
            auto_failed_install_incidents=False,
            auto_reinstall_incidents=True,
        )

        # reported install
        serial_number = get_random_string()
        name = get_random_string()
        version = get_random_string()
        display_name = get_random_string()
        installed_at = datetime.utcnow()

        # existing mi, with failed install
        mi = ManagedInstall.objects.create(
            machine_serial_number=serial_number,
            name=name,
            display_name=get_random_string(),
            installed_version=version,
            installed_at=datetime(1871, 3, 18),
            failed_version=None,
            failed_at=None,
            reinstall=False,  # not a reinstall, will trigger an incident update
        )
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number, name=name)
        self.assertEqual(mi_qs.count(), 1)

        # do apply
        incident_updates = list(apply_managed_installs(
            serial_number,
            [(name, version, display_name, installed_at)],
            configuration
        ))

        # one incident update
        self.assertEqual(len(incident_updates), 1)
        incident_update = incident_updates[0]
        self.assertEqual(incident_update.incident_type, MunkiReinstallIncident.incident_type)
        self.assertEqual(incident_update.key, {"munki_pkginfo_name": name,
                                               "munki_pkginfo_version": version})
        self.assertEqual(incident_update.severity, MunkiReinstallIncident.severity)

        # existing mi updated
        self.assertEqual(mi_qs.count(), 1)
        self._assert_mi_equal(
            mi_qs.first(), mi,
            display_name=display_name,
            installed_at=installed_at,
            reinstall=True,
        )

    def test_a_m_i_one_install_clear_reinstall_no_incident_updates(self):
        configuration = self._force_configuration(
            auto_failed_install_incidents=True,
            auto_reinstall_incidents=False,  # will block the clear reinstall event
        )

        # reported install
        serial_number = get_random_string()
        name = get_random_string()
        version = get_random_string()
        display_name = get_random_string()
        installed_at = datetime.utcnow()

        # existing mi
        mi = ManagedInstall.objects.create(
            machine_serial_number=serial_number,
            name=name,
            display_name=get_random_string(),
            installed_version=get_random_string(),
            installed_at=datetime(1871, 3, 18),
            reinstall=True,  # will be cleared by new install
        )
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number, name=name)
        self.assertEqual(mi_qs.count(), 1)

        # do apply
        incident_updates = list(apply_managed_installs(
            serial_number,
            [(name, version, display_name, installed_at)],
            configuration
        ))

        # no incident updates, because of the configuration
        self.assertEqual(len(incident_updates), 0)

        # existing mi updated
        self.assertEqual(mi_qs.count(), 1)
        self._assert_mi_equal(
            mi_qs.first(), mi,
            display_name=display_name,
            installed_version=version,
            installed_at=installed_at,
            reinstall=False,  # cleared by the more recent install of another version
        )

    def test_a_m_i_one_install_clear_reinstall_one_incident_update(self):
        configuration = self._force_configuration(
            auto_failed_install_incidents=False,
            auto_reinstall_incidents=True,
        )

        # reported install
        serial_number = get_random_string()
        name = get_random_string()
        version = get_random_string()
        display_name = get_random_string()
        installed_at = datetime.utcnow()

        # existing mi
        mi = ManagedInstall.objects.create(
            machine_serial_number=serial_number,
            name=name,
            display_name=get_random_string(),
            installed_version=get_random_string(),
            installed_at=datetime(1871, 3, 18),
            reinstall=True,  # will be cleared by new install
        )
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number, name=name)
        self.assertEqual(mi_qs.count(), 1)

        # do apply
        incident_updates = list(apply_managed_installs(
            serial_number,
            [(name, version, display_name, installed_at)],
            configuration
        ))

        # one incident update
        self.assertEqual(len(incident_updates), 1)
        incident_update = incident_updates[0]
        self.assertEqual(incident_update.incident_type, MunkiReinstallIncident.incident_type)
        self.assertEqual(incident_update.key, {"munki_pkginfo_name": name,
                                               "munki_pkginfo_version": mi.installed_version})
        self.assertEqual(incident_update.severity, Severity.NONE)

        # existing mi updated
        self.assertEqual(mi_qs.count(), 1)
        self._assert_mi_equal(
            mi_qs.first(), mi,
            display_name=display_name,
            installed_version=version,
            installed_at=installed_at,
            reinstall=False,  # cleared by the more recent install of another version
        )

    def test_a_m_i_one_install_delete_other_install_no_incident_updates(self):
        configuration = self._force_configuration(
            auto_failed_install_incidents=True,
            auto_reinstall_incidents=True,
        )

        # reported install
        serial_number = get_random_string()
        name = get_random_string()
        version = get_random_string()
        display_name = get_random_string()
        installed_at = "2019-12-03T09:49:11+00:00"

        # existing mi, without reinstall, without failed install
        old_mi = ManagedInstall.objects.create(
            machine_serial_number=serial_number,
            name=get_random_string(),
            display_name=get_random_string(),
            installed_version=get_random_string(),
            installed_at=datetime(1871, 3, 18),
        )
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number)
        self.assertEqual(mi_qs.count(), 1)

        # do apply
        incident_updates = list(apply_managed_installs(
            serial_number,
            [(name, version, display_name, installed_at)],
            configuration
        ))

        # no incident update
        self.assertEqual(len(incident_updates), 0)

        # new mi, old mi deleted
        self.assertEqual(mi_qs.count(), 1)
        mi = mi_qs.first()
        self.assertNotEqual(mi.pk, old_mi.pk)
        self.assertEqual(mi.name, name)
        self.assertEqual(mi.display_name, display_name)
        self.assertEqual(mi.installed_at, datetime(2019, 12, 3, 9, 49, 11))
        self.assertEqual(mi.installed_version, version)
        self.assertIsNone(mi.failed_at)
        self.assertIsNone(mi.failed_version)
        self.assertFalse(mi.reinstall)

    def test_a_m_i_one_install_delete_other_with_failed_at_no_incident_update(self):
        configuration = self._force_configuration(
            auto_failed_install_incidents=False,  # will block the incident update
            auto_reinstall_incidents=True,
        )

        # reported install
        serial_number = get_random_string()
        name = get_random_string()
        version = get_random_string()
        display_name = get_random_string()
        installed_at = "2019-12-03T09:49:11+00:00"

        # existing mi, without reinstall, with failed install
        old_mi = ManagedInstall.objects.create(
            machine_serial_number=serial_number,
            name=get_random_string(),
            display_name=get_random_string(),
            installed_version=get_random_string(),
            installed_at=datetime(1871, 3, 18),
            failed_version=get_random_string(),  # should trigger an incident update, but blocked by config
            failed_at=datetime(1968, 5, 13),  # should trigger an incident update, but blocked by config
        )
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number)
        self.assertEqual(mi_qs.count(), 1)

        # do apply
        incident_updates = list(apply_managed_installs(
            serial_number,
            [(name, version, display_name, installed_at)],
            configuration
        ))

        # no incident update
        self.assertEqual(len(incident_updates), 0)

        # new mi, old mi deleted
        self.assertEqual(mi_qs.count(), 1)
        mi = mi_qs.first()
        self.assertNotEqual(mi.pk, old_mi.pk)
        self.assertEqual(mi.name, name)
        self.assertEqual(mi.display_name, display_name)
        self.assertEqual(mi.installed_at, datetime(2019, 12, 3, 9, 49, 11))
        self.assertEqual(mi.installed_version, version)
        self.assertIsNone(mi.failed_at)
        self.assertIsNone(mi.failed_version)
        self.assertFalse(mi.reinstall)

    def test_a_m_i_one_install_delete_other_with_failed_at_one_incident_update(self):
        configuration = self._force_configuration(
            auto_failed_install_incidents=True,
            auto_reinstall_incidents=False,
        )

        # reported install
        serial_number = get_random_string()
        name = get_random_string()
        version = get_random_string()
        display_name = get_random_string()
        installed_at = "2019-12-03T09:49:11+00:00"

        # existing mi, without reinstall, with failed install
        old_mi = ManagedInstall.objects.create(
            machine_serial_number=serial_number,
            name=get_random_string(),
            display_name=get_random_string(),
            installed_version=get_random_string(),
            installed_at=datetime(1871, 3, 18),
            failed_version=get_random_string(),  # will trigger an incident update
            failed_at=datetime(1968, 5, 13),  # will trigger an incident update
        )
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number)
        self.assertEqual(mi_qs.count(), 1)

        # do apply
        incident_updates = list(apply_managed_installs(
            serial_number,
            [(name, version, display_name, installed_at)],
            configuration
        ))

        # one incident update
        self.assertEqual(len(incident_updates), 1)
        incident_update = incident_updates[0]
        self.assertEqual(incident_update.incident_type, MunkiFailedInstallIncident.incident_type)
        self.assertEqual(incident_update.key, {"munki_pkginfo_name": old_mi.name,
                                               "munki_pkginfo_version": old_mi.failed_version})
        self.assertEqual(incident_update.severity, Severity.NONE)

        # new mi, old mi deleted
        self.assertEqual(mi_qs.count(), 1)
        mi = mi_qs.first()
        self.assertNotEqual(mi.pk, old_mi.pk)
        self.assertEqual(mi.name, name)
        self.assertEqual(mi.display_name, display_name)
        self.assertEqual(mi.installed_at, datetime(2019, 12, 3, 9, 49, 11))
        self.assertEqual(mi.installed_version, version)
        self.assertIsNone(mi.failed_at)
        self.assertIsNone(mi.failed_version)
        self.assertFalse(mi.reinstall)

    def test_a_m_i_one_install_delete_other_with_reinstall_no_incident_update(self):
        configuration = self._force_configuration(
            auto_failed_install_incidents=True,
            auto_reinstall_incidents=False,  # will block the incident update
        )

        # reported install
        serial_number = get_random_string()
        name = get_random_string()
        version = get_random_string()
        display_name = get_random_string()
        installed_at = "2019-12-03T09:49:11+00:00"

        # existing mi, without reinstall, with failed install
        old_mi = ManagedInstall.objects.create(
            machine_serial_number=serial_number,
            name=get_random_string(),
            display_name=get_random_string(),
            installed_version=get_random_string(),
            installed_at=datetime(1871, 3, 18),
            reinstall=True,  # should trigger an incident update, but blocked by config
        )
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number)
        self.assertEqual(mi_qs.count(), 1)

        # do apply
        incident_updates = list(apply_managed_installs(
            serial_number,
            [(name, version, display_name, installed_at)],
            configuration
        ))

        # no incident update
        self.assertEqual(len(incident_updates), 0)

        # new mi, old mi deleted
        self.assertEqual(mi_qs.count(), 1)
        mi = mi_qs.first()
        self.assertNotEqual(mi.pk, old_mi.pk)
        self.assertEqual(mi.name, name)
        self.assertEqual(mi.display_name, display_name)
        self.assertEqual(mi.installed_at, datetime(2019, 12, 3, 9, 49, 11))
        self.assertEqual(mi.installed_version, version)
        self.assertIsNone(mi.failed_at)
        self.assertIsNone(mi.failed_version)
        self.assertFalse(mi.reinstall)

    def test_a_m_i_one_install_delete_other_with_reinstall_one_incident_update(self):
        configuration = self._force_configuration(
            auto_failed_install_incidents=False,
            auto_reinstall_incidents=True,
        )

        # reported install
        serial_number = get_random_string()
        name = get_random_string()
        version = get_random_string()
        display_name = get_random_string()
        installed_at = "2019-12-03T09:49:11+00:00"

        # existing mi, without reinstall, with failed install
        old_mi = ManagedInstall.objects.create(
            machine_serial_number=serial_number,
            name=get_random_string(),
            display_name=get_random_string(),
            installed_version=get_random_string(),
            installed_at=datetime(1871, 3, 18),
            reinstall=True,  # will trigger an incident update
        )
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=serial_number)
        self.assertEqual(mi_qs.count(), 1)

        # do apply
        incident_updates = list(apply_managed_installs(
            serial_number,
            [(name, version, display_name, installed_at)],
            configuration
        ))

        # one incident update
        self.assertEqual(len(incident_updates), 1)
        incident_update = incident_updates[0]
        self.assertEqual(incident_update.incident_type, MunkiReinstallIncident.incident_type)
        self.assertEqual(incident_update.key, {"munki_pkginfo_name": old_mi.name,
                                               "munki_pkginfo_version": old_mi.installed_version})
        self.assertEqual(incident_update.severity, Severity.NONE)

        # new mi, old mi deleted
        self.assertEqual(mi_qs.count(), 1)
        mi = mi_qs.first()
        self.assertNotEqual(mi.pk, old_mi.pk)
        self.assertEqual(mi.name, name)
        self.assertEqual(mi.display_name, display_name)
        self.assertEqual(mi.installed_at, datetime(2019, 12, 3, 9, 49, 11))
        self.assertEqual(mi.installed_version, version)
        self.assertIsNone(mi.failed_at)
        self.assertIsNone(mi.failed_version)
        self.assertFalse(mi.reinstall)
