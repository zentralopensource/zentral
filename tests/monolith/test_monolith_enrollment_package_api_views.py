from functools import reduce
import json
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import APIToken, User
from zentral.contrib.inventory.models import Tag
from zentral.contrib.monolith.models import ManifestEnrollmentPackage
from zentral.contrib.munki.models import Enrollment as MunkiEnrollment
from tests.munki.utils import force_enrollment as force_munki_enrollment
from .utils import force_manifest, force_manifest_enrollment_package


class MonolithAPIViewsTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        # service account
        cls.service_account = User.objects.create(
            username=get_random_string(12),
            email="{}@zentral.io".format(get_random_string(12)),
            is_service_account=True
        )
        cls.user = User.objects.create_user(
            username=get_random_string(12),
            email="{}@zentral.io".format(get_random_string(12)),
            password=get_random_string(12)
        )
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.service_account.groups.set([cls.group])
        cls.user.groups.set([cls.group])
        _, cls.api_key = APIToken.objects.update_or_create_for_user(user=cls.service_account)

    # utility methods

    def _set_permissions(self, *permissions):
        if permissions:
            permission_filter = reduce(operator.or_, (
                Q(content_type__app_label=app_label, codename=codename)
                for app_label, codename in (
                    permission.split(".")
                    for permission in permissions
                )
            ))
            self.group.permissions.set(list(Permission.objects.filter(permission_filter)))
        else:
            self.group.permissions.clear()

    def _post_data(self, url, data, content_type, include_token=True, ip=None):
        kwargs = {"content_type": content_type}
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.api_key}"
        if ip:
            kwargs["HTTP_X_REAL_IP"] = ip
        return self.client.post(url, data, **kwargs)

    def get(self, url, data=None, include_token=True):
        kwargs = {}
        if data is not None:
            kwargs["data"] = data
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.api_key}"
        return self.client.get(url, **kwargs)

    def delete(self, url, include_token=True):
        kwargs = {}
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.api_key}"
        return self.client.delete(url, **kwargs)

    def post(self, url, data, include_token=True):
        kwargs = {"content_type": "application/json"}
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.api_key}"
        return self.client.post(url, json.dumps(data), **kwargs)

    def put(self, url, data, include_token=True):
        kwargs = {"content_type": "application/json"}
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.api_key}"
        return self.client.put(url, json.dumps(data), **kwargs)

    # list manifest enrollment packages

    def test_get_manifest_enrollment_packages_unauthorized(self):
        response = self.get(reverse("monolith_api:manifest_enrollment_packages"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_manifest_enrollment_packages_permission_denied(self):
        response = self.get(reverse("monolith_api:manifest_enrollment_packages"))
        self.assertEqual(response.status_code, 403)

    def test_get_manifest_enrollment_packages_filter_by_manifest_id_not_found(self):
        self._set_permissions("monolith.view_manifestenrollmentpackage")
        manifest = force_manifest()
        force_manifest_enrollment_package()
        response = self.get(reverse("monolith_api:manifest_enrollment_packages"), {"manifest_id": manifest.pk})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])

    def test_get_manifest_enrollment_packages_filter_by_manifest_id(self):
        mep1 = force_manifest_enrollment_package()
        manifest1 = mep1.manifest
        mep2 = force_manifest_enrollment_package()
        manifest2 = mep2.manifest
        self.assertNotEqual(manifest1, manifest2)
        self._set_permissions("monolith.view_manifestenrollmentpackage")
        response = self.get(reverse("monolith_api:manifest_enrollment_packages"),
                            {"manifest_id": manifest1.id})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            'id': mep1.pk,
            'manifest': manifest1.id,
            'builder': 'zentral.contrib.munki.osx_package.builder.MunkiZentralEnrollPkgBuilder',
            'enrollment_pk': mep1.get_enrollment().pk,
            'version': 1,
            'tags': [],
            'created_at': mep1.created_at.isoformat(),
            'updated_at': mep1.updated_at.isoformat(),
        }])

    def test_get_manifest_enrollment_packages_filter_by_builder(self):
        mep1 = force_manifest_enrollment_package()
        manifest1 = mep1.manifest
        mep1.builder = get_random_string(12)
        mep1.save()
        mep2 = force_manifest_enrollment_package()
        manifest2 = mep2.manifest
        self.assertNotEqual(manifest1, manifest2)
        self._set_permissions("monolith.view_manifestenrollmentpackage")
        response = self.get(reverse("monolith_api:manifest_enrollment_packages"),
                            {"builder": mep2.builder})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            'id': mep2.pk,
            'manifest': manifest2.id,
            'builder': 'zentral.contrib.munki.osx_package.builder.MunkiZentralEnrollPkgBuilder',
            'enrollment_pk': mep2.get_enrollment().pk,
            'version': 1,
            'tags': [],
            'created_at': mep2.created_at.isoformat(),
            'updated_at': mep2.updated_at.isoformat(),
        }])

    def test_get_manifest_enrollment_packages(self):
        mep = force_manifest_enrollment_package()
        self._set_permissions("monolith.view_manifestenrollmentpackage")
        response = self.get(reverse("monolith_api:manifest_enrollment_packages"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            'id': mep.pk,
            'manifest': mep.manifest.id,
            'builder': 'zentral.contrib.munki.osx_package.builder.MunkiZentralEnrollPkgBuilder',
            'enrollment_pk': mep.get_enrollment().pk,
            'version': 1,
            'tags': [],
            'created_at': mep.created_at.isoformat(),
            'updated_at': mep.updated_at.isoformat(),
        }])

    # get manifest enrollment package

    def test_get_manifest_enrollment_package_unauthorized(self):
        response = self.get(reverse("monolith_api:manifest_enrollment_package", args=(9999,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_manifest_enrollment_package_permission_denied(self):
        response = self.get(reverse("monolith_api:manifest_enrollment_package", args=(9999,)))
        self.assertEqual(response.status_code, 403)

    def test_get_manifest_enrollment_package_not_found(self):
        self._set_permissions("monolith.view_manifestenrollmentpackage")
        response = self.get(reverse("monolith_api:manifest_enrollment_package", args=(9999,)))
        self.assertEqual(response.status_code, 404)

    def test_get_manifest_enrollment_package(self):
        tags = [Tag.objects.create(name=get_random_string(12))]
        mep = force_manifest_enrollment_package(tags=tags)
        self._set_permissions("monolith.view_manifestenrollmentpackage")
        response = self.get(reverse("monolith_api:manifest_enrollment_package",
                                    args=(mep.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            'id': mep.pk,
            'manifest': mep.manifest.id,
            'builder': 'zentral.contrib.munki.osx_package.builder.MunkiZentralEnrollPkgBuilder',
            'enrollment_pk': mep.get_enrollment().pk,
            'version': 1,
            'tags': [tags[0].pk],
            'created_at': mep.created_at.isoformat(),
            'updated_at': mep.updated_at.isoformat(),
        })

    # create manifest enrollment package

    def test_create_manifest_enrollment_package_unauthorized(self):
        response = self.post(reverse("monolith_api:manifest_enrollment_packages"),
                             include_token=False, data={})
        self.assertEqual(response.status_code, 401)

    def test_create_manifest_enrollment_package_permission_denied(self):
        response = self.post(reverse("monolith_api:manifest_enrollment_packages"), data={})
        self.assertEqual(response.status_code, 403)

    def test_create_manifest_enrollment_package_fields_empty(self):
        self._set_permissions("monolith.add_manifestenrollmentpackage")
        response = self.post(reverse("monolith_api:manifest_enrollment_packages"), data={})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            'manifest': ['This field is required.'],
            'builder': ['This field is required.'],
            'enrollment_pk': ['This field is required.'],
            'tags': ['This field is required.'],
        })

    def test_create_manifest_enrollment_package_unknown_builder(self):
        self._set_permissions("monolith.add_manifestenrollmentpackage")
        manifest = force_manifest()
        self.assertEqual(manifest.version, 1)
        enrollment = force_munki_enrollment(meta_business_unit=manifest.meta_business_unit)
        response = self.post(reverse("monolith_api:manifest_enrollment_packages"), data={
            'manifest': manifest.pk,
            'builder': 'yolo.fomo',
            'enrollment_pk': enrollment.pk,
            'tags': [],
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'builder': ['Unknown builder']})

    def test_create_manifest_enrollment_package_unknown_enrollment(self):
        self._set_permissions("monolith.add_manifestenrollmentpackage")
        manifest = force_manifest()
        self.assertEqual(manifest.version, 1)
        enrollment = force_munki_enrollment(meta_business_unit=manifest.meta_business_unit)
        response = self.post(reverse("monolith_api:manifest_enrollment_packages"), data={
            'manifest': manifest.pk,
            'builder': 'zentral.contrib.munki.osx_package.builder.MunkiZentralEnrollPkgBuilder',
            'enrollment_pk': enrollment.pk + 1000000,
            'tags': [],
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'non_field_errors': ['Unknown enrollment']})

    def test_create_manifest_enrollment_package_different_business_unit(self):
        self._set_permissions("monolith.add_manifestenrollmentpackage")
        manifest = force_manifest()
        self.assertEqual(manifest.version, 1)
        enrollment = force_munki_enrollment()
        response = self.post(reverse("monolith_api:manifest_enrollment_packages"), data={
            'manifest': manifest.pk,
            'builder': 'zentral.contrib.munki.osx_package.builder.MunkiZentralEnrollPkgBuilder',
            'enrollment_pk': enrollment.pk,
            'tags': [],
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'non_field_errors': ['The manifest and enrollment do not have the same business unit']}
        )

    def test_create_manifest_enrollment_package_enrollment_with_distributor(self):
        self._set_permissions("monolith.add_manifestenrollmentpackage")
        mep = force_manifest_enrollment_package()
        response = self.post(reverse("monolith_api:manifest_enrollment_packages"), data={
            'manifest': mep.manifest.pk,
            'builder': 'zentral.contrib.munki.osx_package.builder.MunkiZentralEnrollPkgBuilder',
            'enrollment_pk': mep.enrollment_pk,
            'tags': [],
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'enrollment_pk': ['This enrollment already has a distributor']})

    def test_create_manifest_enrollment_package(self):
        self._set_permissions("monolith.add_manifestenrollmentpackage")
        manifest = force_manifest()
        self.assertEqual(manifest.version, 1)
        enrollment = force_munki_enrollment(meta_business_unit=manifest.meta_business_unit)
        tag = Tag.objects.create(name=get_random_string(12))
        response = self.post(reverse("monolith_api:manifest_enrollment_packages"), data={
            'manifest': manifest.pk,
            'builder': 'zentral.contrib.munki.osx_package.builder.MunkiZentralEnrollPkgBuilder',
            'enrollment_pk': enrollment.pk,
            'tags': [tag.pk],
        })
        self.assertEqual(response.status_code, 201)
        mep = ManifestEnrollmentPackage.objects.get(
            manifest=manifest,
            builder="zentral.contrib.munki.osx_package.builder.MunkiZentralEnrollPkgBuilder",
            enrollment_pk=enrollment.pk,
        )
        self.assertEqual(response.json(), {
            'id': mep.pk,
            'manifest': manifest.pk,
            'builder': 'zentral.contrib.munki.osx_package.builder.MunkiZentralEnrollPkgBuilder',
            'enrollment_pk': enrollment.pk,
            'tags': [tag.pk],
            'version': 1,
            'created_at': mep.created_at.isoformat(),
            'updated_at': mep.updated_at.isoformat(),
        })
        self.assertEqual(list(t.pk for t in mep.tags.all()), [tag.pk])
        manifest.refresh_from_db()
        self.assertEqual(manifest.version, 2)

    # update manifest enrollment package

    def test_update_manifest_enrollment_package_unauthorized(self):
        response = self.put(reverse("monolith_api:manifest_enrollment_package", args=(9999,)),
                            include_token=False, data={})
        self.assertEqual(response.status_code, 401)

    def test_update_manifest_enrollment_package_permission_denied(self):
        response = self.put(reverse("monolith_api:manifest_enrollment_package", args=(9999,)), data={})
        self.assertEqual(response.status_code, 403)

    def test_update_manifest_enrollment_package_not_found(self):
        self._set_permissions("monolith.change_manifestenrollmentpackage")
        response = self.put(reverse("monolith_api:manifest_enrollment_package", args=(9999,)), data={})
        self.assertEqual(response.status_code, 404)

    def test_update_manifest_enrollment_package(self):
        tags = [Tag.objects.create(name=get_random_string(12))]
        mep = force_manifest_enrollment_package(tags=tags)
        self.assertEqual(mep.tags.count(), 1)
        self.assertEqual(mep.version, 1)
        manifest = mep.manifest
        manifest.refresh_from_db()
        self.assertEqual(manifest.version, 2)
        self._set_permissions("monolith.change_manifestenrollmentpackage")
        response = self.put(
            reverse("monolith_api:manifest_enrollment_package", args=(mep.pk,)),
            data={
                'manifest': manifest.pk,
                'builder': mep.builder,
                'enrollment_pk': mep.enrollment_pk,
                'tags': [],
            }
        )
        self.assertEqual(response.status_code, 200)
        test_mep = ManifestEnrollmentPackage.objects.get(
            manifest=manifest,
            builder=mep.builder,
            enrollment_pk=mep.enrollment_pk,
        )
        self.assertEqual(mep, test_mep)
        self.assertEqual(response.json(), {
            'id': test_mep.pk,
            'manifest': manifest.pk,
            'builder': test_mep.builder,
            'enrollment_pk': test_mep.enrollment_pk,
            'tags': [],
            'version': 2,
            'created_at': test_mep.created_at.isoformat(),
            'updated_at': test_mep.updated_at.isoformat(),
        })
        self.assertEqual(test_mep.tags.count(), 0)
        manifest.refresh_from_db()
        self.assertEqual(manifest.version, 3)

    def test_update_manifest_enrollment_package_update_enrollment(self):
        mep = force_manifest_enrollment_package()
        manifest = mep.manifest
        manifest.refresh_from_db()
        self.assertEqual(manifest.version, 2)
        old_enrollment = mep.get_enrollment()
        self.assertEqual(old_enrollment.distributor, mep)
        new_enrollment = force_munki_enrollment(meta_business_unit=manifest.meta_business_unit)
        self._set_permissions("monolith.change_manifestenrollmentpackage")
        response = self.put(
            reverse("monolith_api:manifest_enrollment_package", args=(mep.pk,)),
            data={
                'manifest': manifest.pk,
                'builder': mep.builder,
                'enrollment_pk': new_enrollment.pk,
                'tags': [],
            }
        )
        self.assertEqual(response.status_code, 200)
        test_mep = ManifestEnrollmentPackage.objects.get(
            manifest=manifest,
            builder=mep.builder,
            enrollment_pk=new_enrollment.pk,
        )
        self.assertEqual(mep, test_mep)
        self.assertEqual(response.json(), {
            'id': test_mep.pk,
            'manifest': manifest.pk,
            'builder': test_mep.builder,
            'enrollment_pk': test_mep.enrollment_pk,
            'tags': [],
            'version': 2,
            'created_at': test_mep.created_at.isoformat(),
            'updated_at': test_mep.updated_at.isoformat(),
        })
        self.assertEqual(test_mep.tags.count(), 0)
        manifest.refresh_from_db()
        self.assertEqual(manifest.version, 3)
        old_enrollment.refresh_from_db()
        self.assertIsNone(old_enrollment.distributor)
        new_enrollment.refresh_from_db()
        self.assertEqual(new_enrollment.distributor, test_mep)

    # delete manifest enrollment package

    def test_delete_manifest_enrollment_package_unauthorized(self):
        response = self.delete(reverse("monolith_api:manifest_enrollment_package", args=(9999,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_manifest_enrollment_package_permission_denied(self):
        response = self.delete(reverse("monolith_api:manifest_enrollment_package", args=(9999,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_manifest_enrollment_package_not_found(self):
        self._set_permissions("monolith.delete_manifestenrollmentpackage")
        response = self.delete(reverse("monolith_api:manifest_enrollment_package", args=(9999,)))
        self.assertEqual(response.status_code, 404)

    def test_delete_manifest_enrollment_package(self):
        mep = force_manifest_enrollment_package()
        enrollment = mep.get_enrollment()
        manifest = mep.manifest
        manifest.refresh_from_db()
        self.assertEqual(manifest.version, 2)
        self._set_permissions("monolith.delete_manifestenrollmentpackage")
        response = self.delete(reverse("monolith_api:manifest_enrollment_package", args=(mep.pk,)))
        self.assertEqual(response.status_code, 204)
        manifest.refresh_from_db()
        self.assertEqual(manifest.version, 3)
        self.assertTrue(MunkiEnrollment.objects.filter(pk=enrollment.pk).exists())
