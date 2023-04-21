from datetime import datetime
from django.test import TestCase
from django.utils.crypto import get_random_string
from django.utils.text import slugify
from zentral.contrib.osquery.compliance_checks import sync_query_compliance_check
from zentral.contrib.osquery.models import Configuration, DistributedQuery, Pack, PackQuery, Query
from zentral.contrib.osquery.terraform import ConfigurationResource, QueryResource


class OsqueryTerraformTestCase(TestCase):

    # utility methods

    def _force_pack(self):
        name = get_random_string(12)
        return Pack.objects.create(name=name, slug=slugify(name))

    def _force_query(self, force_pack=False, force_compliance_check=False, force_distributed_query=False):
        if force_compliance_check:
            sql = "select 'OK' as ztl_status;"
        else:
            sql = "select 1 from processes;"
        query = Query.objects.create(name=get_random_string(12), sql=sql)
        pack = None
        if force_pack:
            pack = self._force_pack()
            PackQuery.objects.create(pack=pack, query=query, interval=12983,
                                     slug=slugify(query.name),
                                     log_removed_actions=False, snapshot_mode=force_compliance_check)
        sync_query_compliance_check(query, force_compliance_check)
        distributed_query = None
        if force_distributed_query:
            distributed_query = DistributedQuery.objects.create(
                query=query,
                query_version=query.version,
                sql=query.sql,
                valid_from=datetime.utcnow()
            )
        return query, pack, distributed_query

    # compliance check

    def test_compliance_check_false(self):
        query, _, _ = self._force_query(force_compliance_check=False)
        resource = QueryResource(query)
        self.assertNotIn("compliance_check_enabled", resource.to_representation())

    def test_compliance_check_true(self):
        query, _, _ = self._force_query(force_compliance_check=True)
        resource = QueryResource(query)
        self.assertIn("compliance_check_enabled = true", resource.to_representation())

    # configuration

    def test_configuration_options_bool(self):
        configuration = Configuration.objects.create(name=get_random_string(12), options={"disable_audit": False})
        resource = ConfigurationResource(configuration)
        self.assertIn('disable_audit = "false"', resource.to_representation())

    def test_configuration_options_int(self):
        configuration = Configuration.objects.create(name=get_random_string(12), options={"config_refresh": 60})
        resource = ConfigurationResource(configuration)
        self.assertIn('config_refresh = "60"', resource.to_representation())
