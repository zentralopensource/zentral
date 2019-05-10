from django.urls import reverse
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.test import APITestCase
from accounts.models import User
from zentral.contrib.inventory.models import MetaBusinessUnit


class InventoryAPITests(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", "GoDziLLaPwD")
        cls.token, _ = Token.objects.get_or_create(user=cls.user)

    def setUp(self):
        super().setUp()
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token.key)

    def test_export_machines(self):
        url = reverse('inventory_api:machines_export')
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("task_id", response.data)
        self.assertIn("task_result_url", response.data)

    def test_create_meta_business_unit(self):
        url = reverse('inventory_api:meta_business_units')
        data = {'name': 'TestMBU0'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(MetaBusinessUnit.objects.filter(name='TestMBU0').count(), 1)
        meta_business_unit = MetaBusinessUnit.objects.get(name='TestMBU0')
        self.assertEqual(meta_business_unit.name, 'TestMBU0')
        self.assertFalse(meta_business_unit.api_enrollment_enabled())

    def test_create_api_enabled_meta_business_unit(self):
        url = reverse('inventory_api:meta_business_units')
        data = {'name': 'TestMBU1', 'api_enrollment_enabled': True}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(MetaBusinessUnit.objects.filter(name='TestMBU1').count(), 1)
        meta_business_unit = MetaBusinessUnit.objects.get(name='TestMBU1')
        self.assertEqual(meta_business_unit.name, 'TestMBU1')
        self.assertTrue(meta_business_unit.api_enrollment_enabled())

    def test_get_meta_business_unit(self):
        meta_business_unit = MetaBusinessUnit.objects.create(name="TestMBU2")
        url = reverse('inventory_api:meta_business_unit', args=(meta_business_unit.pk,))
        response = self.client.get(url, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data,
                         {'id': meta_business_unit.pk,
                          'name': meta_business_unit.name,
                          'api_enrollment_enabled': meta_business_unit.api_enrollment_enabled()})

    def test_update_meta_business_unit(self):
        meta_business_unit = MetaBusinessUnit.objects.create(name="TestMBU3")
        self.assertFalse(meta_business_unit.api_enrollment_enabled())
        url = reverse('inventory_api:meta_business_unit', args=(meta_business_unit.pk,))
        data = {'name': 'TestMBU3.v2', 'api_enrollment_enabled': True}
        response = self.client.put(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        meta_business_unit.refresh_from_db()
        self.assertEqual(meta_business_unit.name, 'TestMBU3.v2')
        self.assertTrue(meta_business_unit.api_enrollment_enabled())
        data = {"name": 'TestMBU3.v2', 'api_enrollment_enabled': False}
        response = self.client.put(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data,
                         {"api_enrollment_enabled": [
                              "Cannot disable API enrollment"
                          ]})

    def test_list_meta_business_unit(self):
        meta_business_unit = MetaBusinessUnit.objects.create(name="TestMBU4")
        url = reverse('inventory_api:meta_business_units')
        response = self.client.get(url, {"name": meta_business_unit.name})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data,
                         [{"id": meta_business_unit.pk,
                           "name": meta_business_unit.name,
                           "api_enrollment_enabled": meta_business_unit.api_enrollment_enabled()}])
