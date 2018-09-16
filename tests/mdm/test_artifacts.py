from datetime import datetime
from django.contrib.contenttypes.models import ContentType
from django.http import HttpResponse
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.models import (DeviceArtifactCommand, EnrolledDevice,
                                        InstalledDeviceArtifact, KernelExtensionPolicy, MDMEnrollmentPackage,
                                        MetaBusinessUnitPushCertificate, PushCertificate)
from zentral.contrib.mdm.views.utils import (get_configured_device_artifact_dict,
                                             get_installed_device_artifact_dict,
                                             iter_next_device_artifact_actions,
                                             get_next_device_artifact_command_response,
                                             get_next_device_command_response,
                                             update_device_artifact_command)


class TestMDMArtifacts(TestCase):
    @classmethod
    def setUpTestData(cls):
        push_certificate = PushCertificate.objects.create(
            name=get_random_string(64),
            topic=get_random_string(256),
            not_before=datetime(2000, 1, 1),
            not_after=datetime(2050, 1, 1),
            certificate=get_random_string(64).encode("utf-8"),
            private_key=get_random_string(64).encode("utf-8")
        )
        cls.meta_business_unit = MetaBusinessUnit.objects.create(name=get_random_string(32))
        cls.meta_business_unit.create_enrollment_business_unit()
        MetaBusinessUnitPushCertificate.objects.create(
            push_certificate=push_certificate,
            meta_business_unit=cls.meta_business_unit
        )
        cls.enrolled_device = EnrolledDevice.objects.create(
            push_certificate=push_certificate,
            serial_number=get_random_string(64),
            udid=get_random_string(36),
            token=get_random_string(32).encode("utf-8"),
            push_magic=get_random_string(73),
            unlock_token=get_random_string(32).encode("utf-8")
        )
        cls.serial_number = cls.enrolled_device.serial_number

    def create_mdm_enrollment_package(self):
        return MDMEnrollmentPackage.objects.create(
            meta_business_unit=self.meta_business_unit,
            builder=get_random_string(256),
            enrollment_pk=17,  # better than 42
            manifest={"yolo": get_random_string(256)}
        )

    def test_no_configured_device_artifacts(self):
        self.assertEqual({}, get_configured_device_artifact_dict(self.meta_business_unit, self.serial_number))

    def test_artifacts_not_for_device(self):
        meta_business_unit2 = MetaBusinessUnit.objects.create(name=get_random_string(32))
        meta_business_unit2.create_enrollment_business_unit()
        KernelExtensionPolicy.objects.create(meta_business_unit=meta_business_unit2)
        self.assertEqual({}, get_configured_device_artifact_dict(self.meta_business_unit, self.serial_number))

    def test_kext_policy_artifact_for_device(self):
        kext_policy = KernelExtensionPolicy.objects.create(meta_business_unit=self.meta_business_unit)
        kext_policy_ct = ContentType.objects.get_for_model(kext_policy)
        self.assertEqual(
            {kext_policy_ct: {kext_policy.pk: kext_policy.version}},
            get_configured_device_artifact_dict(self.meta_business_unit, self.serial_number)
        )

    def test_no_installed_device_artifacts(self):
        self.assertEqual({}, get_installed_device_artifact_dict(self.enrolled_device))

    def test_no_next_device_artifact_action(self):
        self.assertEqual([],
                         list(iter_next_device_artifact_actions(self.meta_business_unit, self.enrolled_device)))

    def test_install_kext_next_device_artifact_action(self):
        kext_policy = KernelExtensionPolicy.objects.create(meta_business_unit=self.meta_business_unit)
        kext_policy_ct = ContentType.objects.get_for_model(kext_policy)
        self.assertEqual([(DeviceArtifactCommand.ACTION_INSTALL, kext_policy_ct, kext_policy)],
                         list(iter_next_device_artifact_actions(self.meta_business_unit, self.enrolled_device)))

    def test_install_application_next_device_artifact_action(self):
        mdm_enrollment_package = self.create_mdm_enrollment_package()
        mdm_enrollment_package_ct = ContentType.objects.get_for_model(mdm_enrollment_package)
        self.assertEqual([(DeviceArtifactCommand.ACTION_INSTALL, mdm_enrollment_package_ct, mdm_enrollment_package)],
                         list(iter_next_device_artifact_actions(self.meta_business_unit, self.enrolled_device)))

    def test_no_next_device_artifact_command_response(self):
        self.assertEqual(None,
                         get_next_device_artifact_command_response(self.meta_business_unit, self.enrolled_device))

    def check_install_profile_command(self, artifact, device_artifact_command, response):
        self.assertIsInstance(response, HttpResponse)
        self.assertEqual(response["Content-Type"], "application/xml; charset=UTF-8")
        self.assertEqual(device_artifact_command.action, DeviceArtifactCommand.ACTION_INSTALL)
        self.assertEqual(device_artifact_command.artifact, artifact)
        self.assertContains(response, "InstallProfile")
        self.assertContains(response, device_artifact_command.command_uuid)

    def test_install_kext_next_device_artifact_command_response(self):
        kext_policy = KernelExtensionPolicy.objects.create(meta_business_unit=self.meta_business_unit)
        response = get_next_device_artifact_command_response(self.meta_business_unit, self.enrolled_device)
        device_artifact_command = DeviceArtifactCommand.objects.all()[0]
        self.check_install_profile_command(kext_policy, device_artifact_command, response)

    def test_install_kext_next_device_command_response(self):
        kext_policy = KernelExtensionPolicy.objects.create(meta_business_unit=self.meta_business_unit)
        response = get_next_device_command_response(self.meta_business_unit, self.enrolled_device)
        device_artifact_command = DeviceArtifactCommand.objects.all()[0]
        self.check_install_profile_command(kext_policy, device_artifact_command, response)

    def check_install_application_command(self, artifact, device_artifact_command, response):
        self.assertIsInstance(response, HttpResponse)
        self.assertEqual(response["Content-Type"], "application/xml; charset=UTF-8")
        self.assertEqual(device_artifact_command.action, DeviceArtifactCommand.ACTION_INSTALL)
        self.assertEqual(device_artifact_command.artifact, artifact)
        self.assertContains(response, "InstallApplication")
        self.assertContains(response, device_artifact_command.command_uuid)
        self.assertContains(response, reverse("mdm:install_application_manifest",
                                              args=(device_artifact_command.command_uuid,)))

    def test_install_application_next_devive_artifact_command_response(self):
        mdm_enrollment_package = self.create_mdm_enrollment_package()
        response = get_next_device_artifact_command_response(self.meta_business_unit, self.enrolled_device)
        device_artifact_command = DeviceArtifactCommand.objects.all()[0]
        self.check_install_application_command(mdm_enrollment_package, device_artifact_command, response)

    def test_install_application_next_device_command_response(self):
        mdm_enrollment_package = self.create_mdm_enrollment_package()
        response = get_next_device_command_response(self.meta_business_unit, self.enrolled_device)
        device_artifact_command = DeviceArtifactCommand.objects.all()[0]
        self.check_install_application_command(mdm_enrollment_package, device_artifact_command, response)

    def test_update_device_artifact_command_acknowledged(self):
        kext_policy = KernelExtensionPolicy.objects.create(meta_business_unit=self.meta_business_unit)
        get_next_device_command_response(self.meta_business_unit, self.enrolled_device)
        device_artifact_command = DeviceArtifactCommand.objects.all()[0]
        device_artifact_command = update_device_artifact_command(
            self.enrolled_device,
            device_artifact_command.command_uuid,
            DeviceArtifactCommand.STATUS_CODE_ACKNOWLEDGED
        )
        # verify that the device_artifact_command has been updated
        self.assertIsInstance(device_artifact_command, DeviceArtifactCommand)
        device_artifact_command.refresh_from_db()
        self.assertEqual(device_artifact_command.status_code, DeviceArtifactCommand.STATUS_CODE_ACKNOWLEDGED)
        # verify that the newly installed artifact is present in the installed device artifacts
        kext_policy_ct = ContentType.objects.get_for_model(kext_policy)
        self.assertEqual({kext_policy_ct: {kext_policy.id: kext_policy.version}},
                         get_installed_device_artifact_dict(self.enrolled_device))
        # verify that there is no new command
        response = get_next_device_command_response(self.meta_business_unit, self.enrolled_device)
        self.assertIsInstance(response, HttpResponse)
        self.assertEqual(response.content, b"")

    def test_remove_kext_next_device_artifact_action(self):
        kext_policy = KernelExtensionPolicy.objects.create(meta_business_unit=self.meta_business_unit)
        kext_policy_ct = ContentType.objects.get_for_model(kext_policy)
        InstalledDeviceArtifact.objects.create(
            enrolled_device=self.enrolled_device,
            artifact_content_type=kext_policy_ct,
            artifact_id=kext_policy.pk,
            artifact_version=kext_policy.version
        )
        # trash the policy
        kext_policy.trashed_at = timezone.now()
        kext_policy.save()
        # verify that a remove command would be scheduled
        self.assertEqual([(DeviceArtifactCommand.ACTION_REMOVE, kext_policy_ct, kext_policy)],
                         list(iter_next_device_artifact_actions(self.meta_business_unit, self.enrolled_device)))

    def test_no_remove_application_next_device_artifact_action(self):
        mdm_enrollment_package = self.create_mdm_enrollment_package()
        mdm_enrollment_package_ct = ContentType.objects.get_for_model(mdm_enrollment_package)
        InstalledDeviceArtifact.objects.create(
            enrolled_device=self.enrolled_device,
            artifact_content_type=mdm_enrollment_package_ct,
            artifact_id=mdm_enrollment_package.pk,
            artifact_version=mdm_enrollment_package.version
        )
        # trash the enrollment package
        mdm_enrollment_package.trashed_at = timezone.now()
        mdm_enrollment_package.save()
        # verify that no remove command would be scheduled, because it is not implemented
        self.assertEqual([],
                         list(iter_next_device_artifact_actions(self.meta_business_unit, self.enrolled_device)))

    def check_remove_profile_command(self, artifact, device_artifact_command, response):
        self.assertIsInstance(response, HttpResponse)
        self.assertEqual(response["Content-Type"], "application/xml; charset=UTF-8")
        self.assertEqual(device_artifact_command.action, DeviceArtifactCommand.ACTION_REMOVE)
        self.assertEqual(device_artifact_command.artifact, artifact)
        self.assertContains(response, "RemoveProfile")
        self.assertContains(response, device_artifact_command.command_uuid)

    def test_remove_kext_next_device_artifact_command_response(self):
        kext_policy = KernelExtensionPolicy.objects.create(meta_business_unit=self.meta_business_unit)
        kext_policy_ct = ContentType.objects.get_for_model(kext_policy)
        InstalledDeviceArtifact.objects.create(
            enrolled_device=self.enrolled_device,
            artifact_content_type=kext_policy_ct,
            artifact_id=kext_policy.pk,
            artifact_version=kext_policy.version
        )
        # trash the policy
        kext_policy.trashed_at = timezone.now()
        kext_policy.save()
        # verify that a remove command would be scheduled
        response = get_next_device_artifact_command_response(self.meta_business_unit, self.enrolled_device)
        device_artifact_command = DeviceArtifactCommand.objects.all()[0]
        self.check_remove_profile_command(kext_policy, device_artifact_command, response)

    def test_remove_kext_next_device_command_response(self):
        kext_policy = KernelExtensionPolicy.objects.create(meta_business_unit=self.meta_business_unit)
        kext_policy_ct = ContentType.objects.get_for_model(kext_policy)
        InstalledDeviceArtifact.objects.create(
            enrolled_device=self.enrolled_device,
            artifact_content_type=kext_policy_ct,
            artifact_id=kext_policy.pk,
            artifact_version=kext_policy.version
        )
        # trash the policy
        kext_policy.trashed_at = timezone.now()
        kext_policy.save()
        # verify that a remove command would be scheduled
        response = get_next_device_artifact_command_response(self.meta_business_unit, self.enrolled_device)
        device_artifact_command = DeviceArtifactCommand.objects.all()[0]
        self.check_remove_profile_command(kext_policy, device_artifact_command, response)

    def test_update_kext_next_device_artifact_action(self):
        kext_policy = KernelExtensionPolicy.objects.create(meta_business_unit=self.meta_business_unit)
        kext_policy.save()  # bump version
        kext_policy.refresh_from_db()
        self.assertEqual(kext_policy.version, 2)
        kext_policy_ct = ContentType.objects.get_for_model(kext_policy)
        InstalledDeviceArtifact.objects.create(
            enrolled_device=self.enrolled_device,
            artifact_content_type=kext_policy_ct,
            artifact_id=kext_policy.pk,
            artifact_version=1
        )
        # verify that an install command would be scheduled
        self.assertEqual([(DeviceArtifactCommand.ACTION_INSTALL, kext_policy_ct, kext_policy)],
                         list(iter_next_device_artifact_actions(self.meta_business_unit, self.enrolled_device)))

    def test_update_enrollment_package_next_device_artifact_action(self):
        mdm_enrollment_package = self.create_mdm_enrollment_package()
        mdm_enrollment_package.refresh_from_db()
        mdm_enrollment_package.version += 1  # bump version
        mdm_enrollment_package.save()
        mdm_enrollment_package_ct = ContentType.objects.get_for_model(mdm_enrollment_package)
        InstalledDeviceArtifact.objects.create(
            enrolled_device=self.enrolled_device,
            artifact_content_type=mdm_enrollment_package_ct,
            artifact_id=mdm_enrollment_package.pk,
            artifact_version=mdm_enrollment_package.version - 1
        )
        # verify that an install command would be scheduled
        self.assertEqual([(DeviceArtifactCommand.ACTION_INSTALL, mdm_enrollment_package_ct, mdm_enrollment_package)],
                         list(iter_next_device_artifact_actions(self.meta_business_unit, self.enrolled_device)))

    def tearDown(self):
        DeviceArtifactCommand.objects.all().delete()
        InstalledDeviceArtifact.objects.all().delete()
        KernelExtensionPolicy.objects.all().delete()
        MDMEnrollmentPackage.objects.all().delete()
