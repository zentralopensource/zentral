from functools import reduce
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.test import APITestCase
from accounts.models import User
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit
from zentral.contrib.inventory.serializers import EnrollmentSecretSerializer
from zentral.contrib.osquery.models import Configuration, Enrollment


class OsqueryAPITests(APITestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string())
        cls.group = Group.objects.create(name=get_random_string())
        cls.user.groups.set([cls.group])
        cls.meta_business_unit = MetaBusinessUnit.objects.create(name=get_random_string())
        cls.token, _ = Token.objects.get_or_create(user=cls.user)

    def setUp(self):
        super().setUp()
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token.key)

    def set_permissions(self, *permissions):
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

    def test_create_configuration(self):
        url = reverse('osquery_api:configurations')
        data = {'name': 'Configuration0'}
        self.set_permissions("osquery.add_configuration")
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Configuration.objects.filter(name='Configuration0').count(), 1)
        configuration0 = Configuration.objects.get(name="Configuration0")
        self.assertEqual(configuration0.name, 'Configuration0')

    def test_get_configuration(self):
        configuration1 = Configuration.objects.create(name="Configuration1")
        url = reverse('osquery_api:configuration', args=(configuration1.pk,))
        self.set_permissions("osquery.view_configuration")
        response = self.client.get(url, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertDictEqual(
            response.data,
            {'id': configuration1.pk,
             'name': configuration1.name,
             'description': "",
             "inventory": True,
             "inventory_apps": False,
             "inventory_interval": 86400,
             "options": {},
             "created_at": configuration1.created_at.isoformat(),
             "updated_at": configuration1.updated_at.isoformat()}
        )

    def test_update_configuration(self):
        configuration2 = Configuration.objects.create(name="Configuration2")
        configuration3 = Configuration.objects.create(name="Configuration3")
        url = reverse('osquery_api:configuration', args=(configuration2.pk,))
        data = {'name': 'Configuration2.v2'}
        self.set_permissions("osquery.change_configuration")
        response = self.client.put(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        configuration2.refresh_from_db()
        self.assertEqual(configuration2.name, 'Configuration2.v2')
        data = {"name": configuration3.name}
        response = self.client.put(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("name", response.data)
        self.assertEqual(response.data["name"][0], "configuration with this name already exists.")

    def test_list_configuration(self):
        configuration4 = Configuration.objects.create(name="Configuration4")
        url = reverse('osquery_api:configurations')
        self.set_permissions("osquery.view_configuration")
        response = self.client.get(url, {"name": configuration4.name})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data,
                         [{"id": configuration4.pk,
                           "name": configuration4.name,
                           'description': "",
                           "inventory": True,
                           "inventory_apps": False,
                           "inventory_interval": 86400,
                           "options": {},
                           "created_at": configuration4.created_at.isoformat(),
                           "updated_at": configuration4.updated_at.isoformat()
                           }])

    def test_delete_configuration(self):
        configuration5 = Configuration.objects.create(name="Configuration5")
        self.set_permissions("osquery.delete_configuration")
        url = reverse('osquery_api:configuration', args=(configuration5.pk,))
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_delete_configuration_error(self):
        configuration6 = Configuration.objects.create(name="Configuration6")
        enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=self.meta_business_unit)
        Enrollment.objects.create(configuration=configuration6, secret=enrollment_secret)
        url = reverse('osquery_api:configuration', args=(configuration6.pk,))
        self.set_permissions("osquery.delete_configuration")
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data, ["This configuration cannot be deleted"])

    def test_create_enrollment(self):
        configuration7 = Configuration.objects.create(name="Configuration7")
        url = reverse('osquery_api:enrollments')
        data = {'configuration': configuration7.pk,
                'secret': {"meta_business_unit": self.meta_business_unit.pk}}
        self.set_permissions("osquery.add_enrollment")
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Enrollment.objects.filter(configuration__name='Configuration7').count(), 1)
        enrollment1 = Enrollment.objects.get(configuration__name="Configuration7")
        self.assertEqual(enrollment1.secret.meta_business_unit, self.meta_business_unit)

    def test_get_enrollment(self):
        configuration8 = Configuration.objects.create(name="Configuration8")
        enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=self.meta_business_unit)
        enrollment2 = Enrollment.objects.create(configuration=configuration8, secret=enrollment_secret)
        url = reverse('osquery_api:enrollment', args=(enrollment2.pk,))
        self.set_permissions("osquery.view_enrollment")
        response = self.client.get(url, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.data,
            {'id': enrollment2.pk,
             'configuration': configuration8.pk,
             'enrolled_machines_count': 0,
             'osquery_release': '',
             'secret': {
                 'id': enrollment_secret.pk,
                 'secret': enrollment_secret.secret,
                 'meta_business_unit': self.meta_business_unit.pk,
                 'tags': [],
                 'serial_numbers': None,
                 'udids': None,
                 'quota': None,
                 'request_count': 0
             },
             'version': 1}
        )

    def test_update_enrollment(self):
        configuration9 = Configuration.objects.create(name="Configuration9")
        enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=self.meta_business_unit)
        enrollment3 = Enrollment.objects.create(configuration=configuration9, secret=enrollment_secret)
        self.assertEqual(enrollment3.osquery_release, "")
        self.assertEqual(enrollment3.secret.quota, None)
        self.assertEqual(enrollment3.secret.serial_numbers, None)
        url = reverse('osquery_api:enrollment', args=(enrollment3.pk,))
        new_osquery_release = get_random_string(12)
        secret_data = EnrollmentSecretSerializer(enrollment_secret).data
        secret_data["id"] = 233333  # to check that there is no enrollment secret creation
        secret_data["quota"] = 23
        secret_data["request_count"] = 2331983  # to check that it cannot be updated
        serial_numbers = [get_random_string(12) for i in range(13)]
        secret_data["serial_numbers"] = serial_numbers
        data = {"configuration": configuration9.pk,
                "osquery_release": new_osquery_release,
                "secret": secret_data}
        self.set_permissions("osquery.change_enrollment")
        response = self.client.put(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        enrollment3.refresh_from_db()
        enrollment_secret.refresh_from_db()
        self.assertEqual(enrollment3.osquery_release, new_osquery_release)
        self.assertEqual(enrollment3.secret, enrollment_secret)
        self.assertEqual(enrollment3.secret.quota, 23)
        self.assertEqual(enrollment_secret.quota, 23)
        self.assertEqual(enrollment3.secret.request_count, 0)
        self.assertEqual(enrollment_secret.request_count, 0)
        self.assertEqual(enrollment3.secret.serial_numbers, serial_numbers)
        self.assertEqual(enrollment_secret.serial_numbers, serial_numbers)

    def test_delete_enrollment(self):
        configuration10 = Configuration.objects.create(name="Configuration10")
        enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=self.meta_business_unit)
        enrollment4 = Enrollment.objects.create(configuration=configuration10, secret=enrollment_secret)
        url = reverse('osquery_api:enrollment', args=(enrollment4.pk,))
        self.set_permissions("osquery.delete_enrollment")
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_delete_enrollment_error(self):
        # TODO: find a enrollment distributor, attach it to the enrollment. Test the 400 response.
        pass

    def test_list_enrollment(self):
        configuration11 = Configuration.objects.create(name="Configuration11")
        enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=self.meta_business_unit)
        enrollment5 = Enrollment.objects.create(configuration=configuration11, secret=enrollment_secret)
        url = reverse('osquery_api:enrollments')
        self.set_permissions("osquery.view_enrollment")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn(
            {'id': enrollment5.pk,
             'configuration': configuration11.pk,
             'enrolled_machines_count': 0,
             'osquery_release': '',
             'secret': {
                 'id': enrollment_secret.pk,
                 'secret': enrollment_secret.secret,
                 'meta_business_unit': self.meta_business_unit.pk,
                 'tags': [],
                 'serial_numbers': None,
                 'udids': None,
                 'quota': None,
                 'request_count': 0
             },
             'version': 1},
            response.data
        )
