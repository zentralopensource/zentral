from django.http import QueryDict
from django.test import TestCase
from zentral.contrib.inventory.utils import MSQuery


class MSQueryTestCase(TestCase):
    def test_unexisting_compliance_check_status_filter(self):
        self.assertEqual("?sf=", MSQuery(QueryDict("sf=ccs.100000000").copy()).get_url())
