from unittest.mock import patch
from django.test import TestCase
from zentral.contrib.mdm.tasks import bulk_assign_location_asset_task
from .utils import force_dep_virtual_server, force_location_asset


class MDMTasksTestCase(TestCase):
    maxDiff = None

    @patch("zentral.contrib.mdm.tasks.bulk_assign_location_asset")
    def test_bulk_assign_location_asset_task(self, bulk_assign_location_asset):
        location_asset = force_location_asset()
        dep_virtual_server = force_dep_virtual_server()
        bulk_assign_location_asset.return_value = 42
        self.assertEqual(
            bulk_assign_location_asset_task(location_asset.pk, [dep_virtual_server.pk]),
            {'dep_virtual_servers': [{'name': dep_virtual_server.name,
                                      'pk': dep_virtual_server.pk,
                                      'uuid': str(dep_virtual_server.uuid)}],
             'location_asset': {'asset': {'adam_id': location_asset.asset.adam_id,
                                          'pk': location_asset.asset.pk,
                                          'pricing_param': location_asset.asset.pricing_param},
                                'location': {'mdm_info_id': str(location_asset.location.mdm_info_id),
                                             'pk': location_asset.location.pk}},
             'total_assignments': 42}
        )
        bulk_assign_location_asset.asset_called_once_with(location_asset, [dep_virtual_server])
