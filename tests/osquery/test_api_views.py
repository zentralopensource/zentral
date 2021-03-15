from functools import reduce
import json
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase
from rest_framework.authtoken.models import Token
from accounts.models import User
from zentral.contrib.osquery.models import Pack, PackQuery, Query


class APIViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.service_account = User.objects.create(
            username=get_random_string(),
            email="{}@zentral.io".format(get_random_string()),
            is_service_account=True
        )
        cls.group = Group.objects.create(name=get_random_string())
        cls.service_account.groups.set([cls.group])
        Token.objects.get_or_create(user=cls.service_account)

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

    def set_pack_endpoint_put_permissions(self):
        self.set_permissions(
            "osquery.add_pack",
            "osquery.change_pack",
            "osquery.add_packquery",
            "osquery.add_query",
            "osquery.change_packquery",
            "osquery.delete_packquery"
        )

    def set_pack_endpoint_delete_permissions(self):
        self.set_permissions(
            "osquery.delete_pack",
            "osquery.delete_packquery",
        )

    def put_data(self, url, data, content_type, include_token=True):
        kwargs = {"content_type": content_type}
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.service_account.auth_token.key}"
        return self.client.put(url, data, **kwargs)

    def delete(self, url, include_token=True):
        kwargs = {}
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.service_account.auth_token.key}"
        return self.client.delete(url, **kwargs)

    def put_json_data(self, url, data, include_token=True):
        content_type = "application/json"
        data = json.dumps(data)
        return self.put_data(url, data, content_type, include_token)

    def test_put_pack_unauthorized(self):
        url = reverse("osquery_api:pack", args=(get_random_string(),))
        response = self.put_json_data(url, {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_put_pack_permission_denied(self):
        url = reverse("osquery_api:pack", args=(get_random_string(),))
        response = self.put_json_data(url, {}, include_token=True)
        self.assertEqual(response.status_code, 403)

    def test_delete_pack_unauthorized(self):
        url = reverse("osquery_api:pack", args=(get_random_string(),))
        response = self.delete(url, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_pack_permission_denied(self):
        url = reverse("osquery_api:pack", args=(get_random_string(),))
        response = self.delete(url, include_token=True)
        self.assertEqual(response.status_code, 403)

    def test_put_no_queries(self):
        self.set_pack_endpoint_put_permissions()
        url = reverse("osquery_api:pack", args=(get_random_string(),))
        response = self.put_json_data(url, {})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'queries': ['This field is required.']}
        )

    def test_put_malformed_query(self):
        self.set_pack_endpoint_put_permissions()
        url = reverse("osquery_api:pack", args=(get_random_string(),))
        response = self.put_json_data(url, {"queries": {"first_query": {"query": ""}}})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'queries': {'first_query': {'interval': ['This field is required.'],
                                         'query': ['This field may not be blank.']}}}
        )

    def test_put_removed_and_snapshot_query(self):
        self.set_pack_endpoint_put_permissions()
        url = reverse("osquery_api:pack", args=(get_random_string(),))
        response = self.put_json_data(
            url,
            {"queries": {"first_query": {"query": "select * from users;",
                                         "interval": 10,
                                         "removed": True,
                                         "snapshot": True}}},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'queries': {
                'first_query': {
                    'non_field_errors': [
                        '{"action": "removed"} results are not available in "snapshot" mode']
                }
            }}
        )

    def test_put_invalid_version_query(self):
        self.set_pack_endpoint_put_permissions()
        url = reverse("osquery_api:pack", args=(get_random_string(),))
        response = self.put_json_data(
            url,
            {"queries": {"first_query": {"query": "select * from users;",
                                         "interval": 10,
                                         "version": "11201hiuhuih"}}},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'queries': {'first_query': {'version': ['This value does not match the required pattern.']}}}
        )

    def test_put_invalid_platform_query(self):
        self.set_pack_endpoint_put_permissions()
        url = reverse("osquery_api:pack", args=(get_random_string(),))
        response = self.put_json_data(
            url,
            {"queries": {"first_query": {"query": "select * from users;",
                                         "interval": 10,
                                         "platform": "rover"}}},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'queries': {'first_query': {'platform': ['Unknown platforms: rover']}}}
        )

    def test_put_invalid_interval_query(self):
        self.set_pack_endpoint_put_permissions()
        url = reverse("osquery_api:pack", args=(get_random_string(),))
        response = self.put_json_data(
            url,
            {"queries": {"first_query": {"query": "select * from users;",
                                         "interval": 10920092820982}}},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'queries': {'first_query': {'interval': ['Ensure this value is less than or equal to 86400.']}}}
        )

    def test_put_invalid_shard_query(self):
        self.set_pack_endpoint_put_permissions()
        url = reverse("osquery_api:pack", args=(get_random_string(),))
        response = self.put_json_data(
            url,
            {"queries": {"first_query": {"query": "select * from users;",
                                         "interval": 10,
                                         "shard": 110}}},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'queries': {'first_query': {'shard': ['Ensure this value is less than or equal to 100.']}}}
        )

    def test_put_name_conflict(self):
        self.set_pack_endpoint_put_permissions()
        Pack.objects.create(slug=get_random_string(), name="Yolo")
        url = reverse("osquery_api:pack", args=(get_random_string(),))
        response = self.put_json_data(
            url,
            {"name": "Yolo",
             "queries": {"first_query": {"query": "select 1 from users;",
                                         "interval": 10}}},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'name': 'A pack with the same name but a different slug already exists'}
        )

    def test_put_pack_json(self):
        self.set_pack_endpoint_put_permissions()
        slug = get_random_string()
        url = reverse("osquery_api:pack", args=(slug,))

        # create pack
        pack = {
            "platform": "darwin",
            "discovery": [
              "select 1 from users where username='root'",
            ],
            "queries": {
                "Leverage-A_1": {
                    "query": "select * from launchd where path like '%UserEvent.System.plist';",
                    "interval": "3600",
                    "version": "1.4.5",
                    "description": (
                        "(http://www.intego.com/mac-security-blog/"
                        "new-mac-trojan-discovered-related-to-syria/)"
                    ),
                    "value": "Artifact used by this malware"
                },
                "Leverage-A_2": {
                    "query": "select * from file where path = '/Users/Shared/UserEvent.app';",
                    "interval": "3600",
                    "version": "1.4.5",
                    "description": (
                        "(http://www.intego.com/mac-security-blog/"
                        "new-mac-trojan-discovered-related-to-syria/)"
                    ),
                    "value": "Artifact used by this malware"
                },
                "Snapshot1": {
                    "query": "select * from users;",
                    "platform": "darwin",
                    "interval": 7200,
                    "snapshot": True,
                    "denylist": False,
                    "shard": 97,
                }
            }
        }
        response = self.put_json_data(url, pack)
        self.assertEqual(response.status_code, 200)
        p = Pack.objects.get(slug=slug)
        self.assertEqual(
            response.json(),
            {'pack': {'pk': p.pk, 'slug': slug},
             'result': 'created',
             'query_results': {'created': 3, 'deleted': 0, 'present': 0, 'updated': 0}}
        )

        # update pack
        pack["name"] = "YOLO"
        response = self.put_json_data(url, pack)
        self.assertEqual(response.status_code, 200)
        p.refresh_from_db()
        self.assertEqual(p.name, "YOLO")
        self.assertEqual(
            response.json(),
            {'pack': {'pk': p.pk, 'slug': slug},
             'result': 'updated',
             'query_results': {'created': 0, 'deleted': 0, 'present': 3, 'updated': 0},
             'updates': {'added': {'name': 'YOLO'}, 'removed': {'name': slug}}}
        )

        # update pack query
        pack_query = p.packquery_set.select_related("query").get(slug="Snapshot1")
        self.assertEqual(pack_query.interval, 7200)
        self.assertEqual(pack_query.query.version, 1)
        pack["queries"]["Snapshot1"]["interval"] = 6789
        response = self.put_json_data(url, pack)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'pack': {'pk': p.pk, 'slug': slug},
             'result': 'present',
             'query_results': {'created': 0, 'deleted': 0, 'present': 2, 'updated': 1}}
        )
        pack_query.refresh_from_db()
        self.assertEqual(pack_query.interval, 6789)
        self.assertEqual(pack_query.query.version, 1)

        # update query
        pack["queries"]["Snapshot1"]["query"] = "select 1 from users;"
        response = self.put_json_data(url, pack)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'pack': {'pk': p.pk, 'slug': slug},
             'result': 'present',
             'query_results': {'created': 0, 'deleted': 0, 'present': 2, 'updated': 1}}
        )
        pack_query.refresh_from_db()
        self.assertEqual(pack_query.query.sql, "select 1 from users;")
        self.assertEqual(pack_query.query.version, 2)

        # delete pack query
        snapshot_1 = pack["queries"].pop("Snapshot1")
        response = self.put_json_data(url, pack)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'pack': {'pk': p.pk, 'slug': slug},
             'result': 'present',
             'query_results': {'created': 0, 'deleted': 1, 'present': 2, 'updated': 0}}
        )
        self.assertEqual(p.packquery_set.filter(slug="Snapshot1").count(), 0)
        query = Query.objects.get(name=f"{slug}{Pack.DELIMITER}Snapshot1")
        with self.assertRaises(PackQuery.DoesNotExist):
            query.packquery

        # re-add pack query with updated query
        snapshot_1["query"] = "select * from users"
        pack["queries"]["Snapshot1"] = snapshot_1
        response = self.put_json_data(url, pack)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'pack': {'pk': p.pk, 'slug': slug},
             'result': 'present',
             'query_results': {'created': 1, 'deleted': 0, 'present': 2, 'updated': 0}}
        )
        query.refresh_from_db()
        self.assertEqual(query.packquery.slug, "Snapshot1")
        self.assertEqual(query.sql, "select * from users")
        self.assertEqual(query.version, 3)

    def test_put_pack_osquery_conf(self):
        self.set_pack_endpoint_put_permissions()
        slug = get_random_string()
        url = reverse("osquery_api:pack", args=(slug,))

        pack = """
        {
          // Do not use this query in production!!!
          "platform": "darwin",
          "queries": {
            "WireLurker": {
              "query" : "select * from launchd where \
                name = 'com.apple.periodic-dd-mm-yy.plist';",
              "interval" : "3600",
              "version": "1.4.5",
              "description" : "(https://github.com/PaloAltoNetworks-BD/WireLurkerDetector)",
              "value" : "Artifact used by this malware - 🔥"
              # 🧨
            }
          }
        }
        """

        response = self.put_data(url, pack.encode("utf-8"), "application/x-osquery-conf", include_token=True)
        self.assertEqual(response.status_code, 200)
        p = Pack.objects.get(slug=slug)
        self.assertEqual(
            response.json(),
            {'pack': {'pk': p.pk, 'slug': slug},
             'result': 'created',
             'query_results': {'created': 1, 'deleted': 0, 'present': 0, 'updated': 0}}
        )
        query = p.packquery_set.first().query
        self.assertEqual(
            query.sql,
            "select * from launchd where                 name = 'com.apple.periodic-dd-mm-yy.plist';"
        )
        self.assertEqual(query.value, "Artifact used by this malware - 🔥")

    def test_put_pack_yaml(self):
        self.set_pack_endpoint_put_permissions()
        slug = get_random_string()
        url = reverse("osquery_api:pack", args=(slug,))

        pack = (
          "---\n"
          "# Do not use this query in production!!!\n\n"
          'platform: "darwin"\n'
          'queries:\n'
          '  WireLurker:\n'
          '    query: >-\n'
          '      select * from launchd where\n'
          "      name = 'com.apple.periodic-dd-mm-yy.plist';\n"
          "    interval: 3600\n"
          "    version: 1.4.5\n"
          "    description: (https://github.com/PaloAltoNetworks-BD/WireLurkerDetector)\n"
          "    value: Artifact used by this malware - 🔥\n"
        )

        response = self.put_data(url, pack.encode("utf-8"), "application/yaml", include_token=True)
        self.assertEqual(response.status_code, 200)
        p = Pack.objects.get(slug=slug)
        self.assertEqual(
            response.json(),
            {'pack': {'pk': p.pk, 'slug': slug},
             'result': 'created',
             'query_results': {'created': 1, 'deleted': 0, 'present': 0, 'updated': 0}}
        )
        query = p.packquery_set.first().query
        self.assertEqual(
            query.sql,
            "select * from launchd where name = 'com.apple.periodic-dd-mm-yy.plist';"
        )
        self.assertEqual(query.value, "Artifact used by this malware - 🔥")

    def test_delete_pack_404(self):
        self.set_pack_endpoint_delete_permissions()
        slug = get_random_string()
        url = reverse("osquery_api:pack", args=(slug,))
        response = self.delete(url, include_token=True)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(
            response.json(),
            {"pack": {"slug": slug}, "result": "absent"}
        )

    def test_delete_pack(self):
        slug = get_random_string()
        url = reverse("osquery_api:pack", args=(slug,))

        # create pack
        pack = {
            "platform": "darwin",
            "discovery": [
              "select 1 from users where username='root'",
            ],
            "queries": {
                "Leverage-A_1": {
                    "query": "select * from launchd where path like '%UserEvent.System.plist';",
                    "interval": "3600",
                    "version": "1.4.5",
                    "description": (
                        "(http://www.intego.com/mac-security-blog/"
                        "new-mac-trojan-discovered-related-to-syria/)"
                    ),
                    "value": "Artifact used by this malware"
                },
                "Leverage-A_2": {
                    "query": "select * from file where path = '/Users/Shared/UserEvent.app';",
                    "interval": "3600",
                    "version": "1.4.5",
                    "description": (
                        "(http://www.intego.com/mac-security-blog/"
                        "new-mac-trojan-discovered-related-to-syria/)"
                    ),
                    "value": "Artifact used by this malware"
                },
                "Snapshot1": {
                    "query": "select * from users;",
                    "platform": "darwin",
                    "interval": 7200,
                    "snapshot": True,
                    "denylist": False,
                    "shard": 97,
                }
            }
        }
        self.set_pack_endpoint_put_permissions()
        self.put_json_data(url, pack)
        p = Pack.objects.get(slug=slug)

        # delete pack
        self.set_pack_endpoint_delete_permissions()
        response = self.delete(url, include_token=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'pack': {'pk': p.pk, 'slug': slug},
             'result': 'deleted',
             'query_results': {'created': 0, 'deleted': 3, 'present': 0, 'updated': 0}}
        )
