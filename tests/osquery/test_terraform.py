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

    # pack query

    def test_pack_query(self):
        query, pack, _ = self._force_query(force_pack=True)
        resource = QueryResource(query)
        self.assertIn(
          "scheduling = { interval = 12983, log_removed_actions = false, "
          f"pack_id = zentral_osquery_pack.pack{ pack.id}.id }}",
          resource.to_representation()
        )

    # compliance check

    def test_compliance_check_false(self):
        query, _, _ = self._force_query(force_compliance_check=False)
        resource = QueryResource(query)
        resource_repr = resource.to_representation()
        self.assertNotIn("compliance_check_enabled", resource_repr)
        self.assertNotIn("scheduling", resource_repr)

    def test_compliance_check_true(self):
        query, _, _ = self._force_query(force_compliance_check=True)
        resource = QueryResource(query)
        resource_repr = resource.to_representation()
        self.assertIn("compliance_check_enabled = true", resource_repr)
        self.assertNotIn("scheduling", resource_repr)

    # configuration

    def test_configuration_options_bool(self):
        configuration = Configuration.objects.create(name=get_random_string(12), options={"disable_audit": False})
        resource = ConfigurationResource(configuration)
        self.assertIn('disable_audit = "false"', resource.to_representation())

    def test_configuration_options_int(self):
        configuration = Configuration.objects.create(name=get_random_string(12), options={"config_refresh": 60})
        resource = ConfigurationResource(configuration)
        self.assertIn('config_refresh = "60"', resource.to_representation())
