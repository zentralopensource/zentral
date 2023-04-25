from datetime import datetime
from functools import reduce
import json
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.utils.text import slugify
from django.utils.http import http_date
from django.test import TestCase, override_settings
from accounts.models import APIToken, User
from zentral.conf import settings
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit, Tag
from zentral.contrib.inventory.serializers import EnrollmentSecretSerializer
from zentral.contrib.osquery.compliance_checks import sync_query_compliance_check
from zentral.contrib.osquery.models import (Configuration, DistributedQuery, Enrollment, Pack, PackQuery, Query,
                                            AutomaticTableConstruction, FileCategory, ConfigurationPack)
from zentral.core.compliance_checks.models import ComplianceCheck


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class APIViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.service_account = User.objects.create(
            username=get_random_string(12),
            email="{}@zentral.io".format(get_random_string(12)),
            is_service_account=True
        )
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.service_account.groups.set([cls.group])
        cls.user.groups.set([cls.group])
        cls.api_key = APIToken.objects.update_or_create_for_user(cls.service_account)
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()

    # utility methods

    def force_configuration(self, force_atc=False, force_file_category=False, force_pack=False):
        if force_atc:
            atc = self.force_atc()
            conf = Configuration.objects.create(name=get_random_string(12))
            conf.automatic_table_constructions.set([atc])
            return conf, atc
        if force_file_category:
            file_category = self.force_file_category()
            conf = Configuration.objects.create(name=get_random_string(12))
            conf.file_categories.set([file_category])
            return conf, file_category
        if force_pack:
            pack = self.force_pack()
            conf = Configuration.objects.create(name=get_random_string(12))
            conf_pack = ConfigurationPack.objects.create(
                pack=pack,
                configuration=conf
            )
            return conf, pack, conf_pack
        return Configuration.objects.create(name=get_random_string(12))

    def force_tags(self, count=1):
        return [Tag.objects.create(name=get_random_string(12)) for _ in range(count)]

    def force_configuration_pack(self, force_tags=False):
        _, _, configuration_pack = self.force_configuration(force_pack=True)
        if force_tags:
            tag = self.force_tags(1)
            configuration_pack.tags.set(tag)
        return configuration_pack

    def force_enrollment(self, tag_count=0):
        configuration = self.force_configuration()
        enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=self.mbu)
        tags = [Tag.objects.create(name=get_random_string(12)) for _ in range(tag_count)]
        if tags:
            enrollment_secret.tags.set(tags)
        return (
            Enrollment.objects.create(configuration=configuration, secret=enrollment_secret),
            tags
        )

    def force_atc(self, **kwargs):
        atc = {
            "name": get_random_string(12),
            "description": get_random_string(12),
            "table_name": get_random_string(length=12, allowed_chars="abcd_"),
            "query": "select 1 from yo;",
            "path": "/home/yolo",
            "columns": ["un", "deux"],
            "platforms": ["darwin", "windows"],
        }
        atc.update(**kwargs)
        return AutomaticTableConstruction.objects.create(**atc)

    def force_file_category(self):
        name = get_random_string(12).lower()
        slug = slugify(name)

        return FileCategory.objects.create(
            name=name,
            slug=slug,
            file_paths=['/home/yo'],
            description='description of the file category',
            exclude_paths=['/home/yo/exclude1', '/home/yo/exclude2'],
            access_monitoring=False,
            file_paths_queries=['select * from file_paths where path like "/home/yo/";'],
        )

    def force_pack(self):
        name = get_random_string(12)
        return Pack.objects.create(name=name.lower(), slug=slugify(name))

    def force_query(self, query_name=None, pack_query_mode=None, compliance_check=False):
        if query_name:
            name = query_name
        else:
            name = get_random_string(12).lower()
        slug = slugify(name)
        if compliance_check:
            sql = "select 'OK' as ztl_status;"
        else:
            sql = "SELECT * FROM osquery_schedule;"
        query = Query.objects.create(name=name, sql=sql)
        if pack_query_mode is not None:
            pack = self.force_pack()
            if pack_query_mode == "diff":
                PackQuery.objects.create(
                    pack=pack, query=query, interval=60, slug=slug, log_removed_actions=False,
                    snapshot_mode=False)
            elif pack_query_mode == "snapshot":
                PackQuery.objects.create(
                    pack=pack, query=query, interval=60, slug=slug, log_removed_actions=False,
                    snapshot_mode=True)
        sync_query_compliance_check(query, compliance_check)
        query.refresh_from_db()
        return query

    def force_pack_query(self, query_name=None, force_snapshot_mode=False, compliance_check=False):
        if force_snapshot_mode:
            pack_query_mode = "snapshot"
        else:
            pack_query_mode = "diff"

        return self.force_query(
            query_name=query_name,
            pack_query_mode=pack_query_mode,
            compliance_check=compliance_check
        ).packquery

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

    def login(self, *permissions):
        self.set_permissions(*permissions)
        self.client.force_login(self.user)

    def login_redirect(self, url):
        response = self.client.get(url)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def get(self, url, data=None, include_token=True):
        kwargs = {}
        if data is not None:
            kwargs["data"] = data
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.api_key}"
        return self.client.get(url, **kwargs)

    def post(self, url, include_token=True):
        kwargs = {}
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.api_key}"
        return self.client.post(url, **kwargs)

    def post_json_data(self, url, data, include_token=True):
        kwargs = {'content_type': 'application/json',
                  'data': data}
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.api_key}"
        return self.client.post(url, **kwargs)

    def put_data(self, url, data, content_type, include_token=True):
        kwargs = {"content_type": content_type}
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.api_key}"
        return self.client.put(url, data, **kwargs)

    def delete(self, url, include_token=True):
        kwargs = {}
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.api_key}"
        return self.client.delete(url, **kwargs)

    def put_json_data(self, url, data, include_token=True):
        content_type = "application/json"
        data = json.dumps(data)
        return self.put_data(url, data, content_type, include_token)

    # list atcs

    def test_get_atcs_unauthorized(self):
        response = self.get(reverse("osquery_api:atcs"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_atcs_permission_denied(self):
        response = self.get(reverse("osquery_api:atcs"))
        self.assertEqual(response.status_code, 403)

    def test_get_atcs_filter_by_name_not_found(self):
        self.set_permissions("osquery.view_automatictableconstruction")
        response = self.get(reverse('osquery_api:atcs'), data={"name": get_random_string(24)})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])

    def test_get_atcs_filter_by_configuration_id_not_found(self):
        self.set_permissions("osquery.view_automatictableconstruction")
        response = self.get(reverse('osquery_api:atcs'), data={"configuration_id": 99999})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"configuration_id": ["Select a valid choice. That choice is not one of the "
                                                                "available choices."]})

    def test_get_atcs_filter_by_name(self):
        for _ in range(3):
            self.force_atc()
        atc = self.force_atc()
        self.set_permissions("osquery.view_automatictableconstruction")
        response = self.get(reverse('osquery_api:atcs'), data={"name": atc.name})
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.json(), list)
        self.assertEqual(response.json(), [{
            "platforms": ["darwin", "windows"],
            "updated_at": atc.updated_at.isoformat(),
            "columns": ["un", "deux"],
            "id": atc.id,
            "created_at": atc.created_at.isoformat(),
            "table_name": atc.table_name,
            "query": "select 1 from yo;",
            "description": atc.description,
            "path": "/home/yolo",
            "name": atc.name
        }])

    def test_get_atcs_filter_by_configuration_id(self):
        for _ in range(3):
            self.force_configuration(force_atc=True)
        configuration, atc = self.force_configuration(force_atc=True)
        self.set_permissions("osquery.view_automatictableconstruction")
        response = self.get(reverse('osquery_api:atcs'), data={"configuration_id": configuration.id})
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.json(), list)
        self.assertEqual(response.json(), [{
            "platforms": ["darwin", "windows"],
            "updated_at": atc.updated_at.isoformat(),
            "columns": ["un", "deux"],
            "id": atc.id,
            "created_at": atc.created_at.isoformat(),
            "table_name": atc.table_name,
            "query": "select 1 from yo;",
            "description": atc.description,
            "path": "/home/yolo",
            "name": atc.name
        }])

    def test_get_atcs(self):
        atc = self.force_atc()
        self.set_permissions("osquery.view_automatictableconstruction")
        response = self.get(reverse('osquery_api:atcs'))
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.json(), list)
        self.assertEqual(response.json(), [{
            "platforms": ["darwin", "windows"],
            "updated_at": atc.updated_at.isoformat(),
            "columns": ["un", "deux"],
            "id": atc.id,
            "created_at": atc.created_at.isoformat(),
            "table_name": atc.table_name,
            "query": "select 1 from yo;",
            "description": atc.description,
            "path": "/home/yolo",
            "name": atc.name
        }])

    # get atc

    def test_get_atc_unauthorized(self):
        response = self.get(reverse("osquery_api:atc", args=[1]), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_atc_permission_denied(self):
        response = self.get(reverse("osquery_api:atc", args=[1]))
        self.assertEqual(response.status_code, 403)

    def test_get_atc_not_found(self):
        self.set_permissions("osquery.view_automatictableconstruction")
        response = self.get(reverse("osquery_api:atc", args=[99999]))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {
            "detail": "Not found."
        })

    def test_get_atc(self):
        atc = self.force_atc()
        self.set_permissions("osquery.view_automatictableconstruction")
        response = self.get(reverse("osquery_api:atc", args=[atc.id]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            "platforms": ["darwin", "windows"],
            "updated_at": atc.updated_at.isoformat(),
            "columns": ["un", "deux"],
            "id": atc.id,
            "created_at": atc.created_at.isoformat(),
            "table_name": atc.table_name,
            "query": "select 1 from yo;",
            "description": atc.description,
            "path": "/home/yolo",
            "name": atc.name
        })

    # update atc

    def test_update_atc_unauthorized(self):
        response = self.put_json_data(reverse("osquery_api:atc", args=[1]), {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_update_atc_permission_denied(self):
        response = self.put_json_data(reverse("osquery_api:atc", args=[1]), {})
        self.assertEqual(response.status_code, 403)

    def test_update_atc_name_conflict(self):
        _, atc = self.force_configuration(force_atc=True)
        _, atc2 = self.force_configuration(force_atc=True)
        self.set_permissions("osquery.change_automatictableconstruction")
        data = {
            "name": atc.name,
            "description": "yolo changed",
            "path": "/home/yolo/new",
            "query": "select new from yolo;",
            "table_name": "yolo_new",
            "columns": ["un", "deux", "trois"],
            "platforms": ["darwin"]
        }
        response = self.put_json_data(reverse("osquery_api:atc", args=[atc2.id]), data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "name": ["automatic table construction with this name already exists."]
        })

    def test_update_atc_fields_empty(self):
        atc = self.force_atc()
        self.set_permissions("osquery.change_automatictableconstruction")
        data = {
            "name": "",
            "path": "",
            "query": "",
            "table_name": "",
            "columns": [],
            "platforms": []
        }
        response = self.put_json_data(reverse("osquery_api:atc", args=[atc.id]), data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "name": ["This field may not be blank."],
            "path": ["This field may not be blank."],
            "query": ["This field may not be blank."],
            "table_name": ["This field may not be blank."],
            "columns": ["This list may not be empty."]
        })

    def test_update_atc_not_found(self):
        self.set_permissions("osquery.change_automatictableconstruction")
        response = self.put_json_data(reverse("osquery_api:atc", args=[9999]), {})
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {
            "detail": "Not found."
        })

    def test_update_atc(self):
        atc = self.force_atc()
        self.set_permissions("osquery.change_automatictableconstruction")
        data = {
            "name": "yolo",
            "description": "yolo changed",
            "path": "/home/yolo/new",
            "query": "select new from yolo;",
            "table_name": "yolo_new",
            "columns": ["un", "deux", "trois"],
            "platforms": ["darwin"]
        }
        response = self.put_json_data(reverse("osquery_api:atc", args=[atc.id]), data)
        self.assertEqual(response.status_code, 200)
        atc.refresh_from_db()
        self.assertEqual(response.json(), {
            "platforms": ["darwin"],
            "updated_at": atc.updated_at.isoformat(),
            "columns": ["un", "deux", "trois"],
            "id": atc.id,
            "created_at": atc.created_at.isoformat(),
            "table_name": "yolo_new",
            "query": "select new from yolo;",
            "description": "yolo changed",
            "path": "/home/yolo/new",
            "name": atc.name
        })
        self.assertEqual(atc.path, "/home/yolo/new")
        self.assertEqual(atc.query, "select new from yolo;")
        self.assertEqual(atc.table_name, "yolo_new")
        self.assertEqual(atc.columns, ["un", "deux", "trois"])
        self.assertEqual(atc.platforms, ["darwin"])
        self.assertEqual(atc.description, "yolo changed")

    # create atc

    def test_create_atc_unauthorized(self):
        response = self.post(reverse("osquery_api:atcs"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_create_atc_permission_denied(self):
        response = self.post(reverse("osquery_api:atcs"))
        self.assertEqual(response.status_code, 403)

    def test_create_atc_name_conflict(self):
        atc = self.force_atc()
        self.set_permissions("osquery.add_automatictableconstruction")
        response = self.post_json_data(reverse("osquery_api:atcs"), {
            "name": atc.name,
            "description": "yolo",
            "table_name": "yolo",
            "query": "select 1 from yo;",
            "columns": ["un", "deux"],
            "platforms": ["darwin", "windows"],
            "path": "/home/yolo"
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "name": ["automatic table construction with this name already exists."]
        })

    def test_create_atc_fields_empty(self):
        self.set_permissions("osquery.add_automatictableconstruction")
        data = {
            "name": "",
            "path": "",
            "query": "",
            "table_name": "",
            "columns": [],
            "platforms": []
        }
        response = self.post_json_data(reverse("osquery_api:atcs"), data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "name": ["This field may not be blank."],
            "path": ["This field may not be blank."],
            "query": ["This field may not be blank."],
            "table_name": ["This field may not be blank."],
            "columns": ["This list may not be empty."]
        })

    def test_create_atc(self):
        self.set_permissions("osquery.add_automatictableconstruction")
        response = self.post_json_data(reverse("osquery_api:atcs"), {
            "name": "yolo",
            "description": "yolo",
            "table_name": "yolo",
            "query": "select 1 from yo;",
            "columns": ["un", "deux"],
            "platforms": ["darwin", "windows"],
            "path": "/home/yolo"
        })
        self.assertEqual(response.status_code, 201)
        atc = AutomaticTableConstruction.objects.first()
        self.assertEqual(response.json(), {
            "platforms": ["darwin", "windows"],
            "updated_at": atc.updated_at.isoformat(),
            "columns": ["un", "deux"],
            "id": atc.id,
            "created_at": atc.created_at.isoformat(),
            "table_name": "yolo",
            "query": "select 1 from yo;",
            "description": "yolo",
            "path": "/home/yolo",
            "name": "yolo"
        })
        self.assertEqual(atc.name, "yolo")
        self.assertEqual(atc.description, "yolo")
        self.assertEqual(atc.table_name, "yolo")
        self.assertEqual(atc.query, "select 1 from yo;")
        self.assertEqual(atc.columns, ["un", "deux"])
        self.assertEqual(atc.platforms, ["darwin", "windows"])
        self.assertEqual(atc.path, "/home/yolo")

    # delete atc

    def test_delete_atc_unauthorized(self):
        response = self.delete(reverse("osquery_api:atc", args=[1]), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_atc_permission_denied(self):
        response = self.delete(reverse("osquery_api:atc", args=[1]))
        self.assertEqual(response.status_code, 403)

    def test_delete_atc_not_found(self):
        self.set_permissions("osquery.delete_automatictableconstruction")
        response = self.delete(reverse("osquery_api:atc", args=[9999]))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {
            "detail": "Not found."
        })

    def test_delete_atc(self):
        atc = self.force_atc()
        self.set_permissions("osquery.delete_automatictableconstruction")
        response = self.delete(reverse("osquery_api:atc", args=[atc.id]))
        self.assertEqual(response.status_code, 204)
        self.assertFalse(AutomaticTableConstruction.objects.exists())

    # list file categories

    def test_get_file_categories_unauthorized(self):
        response = self.get(reverse("osquery_api:file_categories"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_file_categories_permission_denied(self):
        response = self.get(reverse("osquery_api:file_categories"))
        self.assertEqual(response.status_code, 403)

    def test_get_file_categories_filter_by_name_not_found(self):
        self.set_permissions("osquery.view_filecategory")
        response = self.get(reverse('osquery_api:file_categories'), data={"name": get_random_string(35)})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])

    def test_get_file_categories_filter_by_configuration_id_not_found(self):
        self.set_permissions("osquery.view_filecategory")
        response = self.get(reverse('osquery_api:file_categories'), data={"configuration_id": 9999})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"configuration_id": ["Select a valid choice. "
                                                                "That choice is not one of the available choices."]})

    def test_get_file_categories_filter_by_name(self):
        for _ in range(3):
            self.force_file_category()
        file_category = self.force_file_category()
        self.set_permissions("osquery.view_filecategory")
        response = self.get(reverse('osquery_api:file_categories'), data={"name": file_category.name})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            "name": file_category.name,
            "slug": file_category.slug,
            "id": file_category.id,
            "file_paths": ['/home/yo'],
            "exclude_paths": ['/home/yo/exclude1', '/home/yo/exclude2'],
            "access_monitoring": False,
            "description": "description of the file category",
            "file_paths_queries": ['select * from file_paths where path like "/home/yo/";'],
            "updated_at": file_category.updated_at.isoformat(),
            "created_at": file_category.created_at.isoformat(),
        }])

    def test_get_file_categories_filter_by_configuration_id(self):
        for _ in range(3):
            self.force_configuration(force_file_category=True)
        configuration, file_category = self.force_configuration(force_file_category=True)
        self.set_permissions("osquery.view_filecategory")
        response = self.get(reverse('osquery_api:file_categories'),
                            data={"configuration_id": configuration.id})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            "name": file_category.name,
            "slug": file_category.slug,
            "id": file_category.id,
            "file_paths": ['/home/yo'],
            "exclude_paths": ['/home/yo/exclude1', '/home/yo/exclude2'],
            "access_monitoring": False,
            "description": "description of the file category",
            "file_paths_queries": ['select * from file_paths where path like "/home/yo/";'],
            "updated_at": file_category.updated_at.isoformat(),
            "created_at": file_category.created_at.isoformat(),
        }])

    def test_get_file_categories(self):
        file_category = self.force_file_category()
        self.set_permissions("osquery.view_filecategory")
        response = self.get(reverse('osquery_api:file_categories'))
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.json(), list)
        self.assertEqual(response.json(), [{
            "name": file_category.name,
            "slug": file_category.slug,
            "id": file_category.id,
            "file_paths": ['/home/yo'],
            "exclude_paths": ['/home/yo/exclude1', '/home/yo/exclude2'],
            "access_monitoring": False,
            "description": "description of the file category",
            "file_paths_queries": ['select * from file_paths where path like "/home/yo/";'],
            "updated_at": file_category.updated_at.isoformat(),
            "created_at": file_category.created_at.isoformat(),
        }])

    # get file category

    def test_get_file_category_unauthorized(self):
        response = self.get(reverse("osquery_api:file_category", args=[1]), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_file_category_permission_denied(self):
        response = self.get(reverse("osquery_api:file_category", args=[1]))
        self.assertEqual(response.status_code, 403)

    def test_get_file_category_not_found(self):
        self.set_permissions("osquery.view_filecategory")
        response = self.get(reverse("osquery_api:file_category", args=[9999]))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {
            "detail": "Not found."
        })

    def test_get_file_category(self):
        file_category = self.force_file_category()
        self.set_permissions("osquery.view_filecategory")
        response = self.get(reverse("osquery_api:file_category", args=[file_category.id]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            "name": file_category.name,
            "slug": file_category.slug,
            "id": file_category.id,
            "file_paths": ['/home/yo'],
            "exclude_paths": ['/home/yo/exclude1', '/home/yo/exclude2'],
            "access_monitoring": False,
            "description": "description of the file category",
            "file_paths_queries": ['select * from file_paths where path like "/home/yo/";'],
            "updated_at": file_category.updated_at.isoformat(),
            "created_at": file_category.created_at.isoformat(),
        })

    # update file category

    def test_update_file_category_unauthorized(self):
        response = self.put_json_data(reverse("osquery_api:file_category", args=[1]), {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_update_file_category_permission_denied(self):
        response = self.put_json_data(reverse("osquery_api:file_category", args=[1]), {})
        self.assertEqual(response.status_code, 403)

    def test_update_file_category_slug_conflict(self):
        file_category = self.force_file_category()
        file_category2 = self.force_file_category()
        self.set_permissions("osquery.change_filecategory")
        data = {"name": file_category.name.upper()}
        response = self.put_json_data(reverse("osquery_api:file_category", args=[file_category2.id]), data=data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "name": [f"file category with this slug {file_category.slug} already exists."]
        })

    def test_update_file_category_name_conflict(self):
        file_category = self.force_file_category()
        file_category2 = self.force_file_category()
        self.set_permissions("osquery.change_filecategory")
        data = {"name": file_category.name}
        response = self.put_json_data(reverse("osquery_api:file_category", args=[file_category2.id]), data=data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "name": ["file category with this name already exists."]
        })

    def test_update_file_category_fields_empty(self):
        file_category = self.force_file_category()
        self.set_permissions("osquery.change_filecategory")
        data = {
            "name": "",
            "description": "",
            "file_paths": [],
            "exclude_paths": [],
            "file_paths_queries": [],
            "access_monitoring": None,
        }
        response = self.put_json_data(reverse("osquery_api:file_category", args=[file_category.id]), data=data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "name": ["This field may not be blank."],
            "access_monitoring": ["This field may not be null."],
        })

    def test_update_file_category_not_found(self):
        self.set_permissions("osquery.change_filecategory")
        response = self.put_json_data(reverse("osquery_api:file_category", args=[9999]), {})
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {
            "detail": "Not found."
        })

    def test_update_file_category(self):
        file_category = self.force_file_category()
        self.set_permissions("osquery.change_filecategory")
        data = {
            "name": "file category name",
            "file_paths": ['/home/yo/bin'],
            "exclude_paths": ['/home/you/exclude', '/home/me/exclude'],
            "description": "description of the example file category",
            "file_paths_queries": [],
            "access_monitoring": True
        }
        response = self.put_json_data(reverse("osquery_api:file_category", args=[file_category.id]), data=data)
        self.assertEqual(response.status_code, 200)
        file_category.refresh_from_db()
        self.assertEqual(response.json(), {
            "name": "file category name",
            "slug": slugify("file category name"),
            "id": file_category.id,
            "file_paths": ['/home/yo/bin'],
            "exclude_paths": ['/home/you/exclude', '/home/me/exclude'],
            "access_monitoring": True,
            "description": "description of the example file category",
            "file_paths_queries": [],
            "updated_at": file_category.updated_at.isoformat(),
            "created_at": file_category.created_at.isoformat(),
        })
        self.assertEqual(file_category.name, "file category name")
        self.assertEqual(file_category.slug, slugify("file category name"))
        self.assertEqual(file_category.file_paths, ['/home/yo/bin'])
        self.assertEqual(file_category.exclude_paths, ['/home/you/exclude', '/home/me/exclude'])
        self.assertEqual(file_category.access_monitoring, True)
        self.assertEqual(file_category.description, "description of the example file category")
        self.assertEqual(file_category.file_paths_queries, [])

    # create file category

    def test_create_file_category_unauthorized(self):
        response = self.post(reverse("osquery_api:file_categories"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_create_file_category_permission_denied(self):
        response = self.post(reverse("osquery_api:file_categories"))
        self.assertEqual(response.status_code, 403)

    def test_create_file_category_slug_conflict(self):
        file_category = self.force_file_category()
        self.set_permissions("osquery.add_filecategory")
        data = {"name": file_category.name.upper()}
        response = self.post_json_data(reverse("osquery_api:file_categories"), data=data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "name": [f"file category with this slug {file_category.slug} already exists."]
        })

    def test_create_file_category_name_conflict(self):
        file_category = self.force_file_category()
        self.set_permissions("osquery.add_filecategory")
        data = {"name": file_category.name}
        response = self.post_json_data(reverse("osquery_api:file_categories"), data=data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "name": ["file category with this name already exists."]
        })

    def test_create_file_category_fields_empty(self):
        self.set_permissions("osquery.add_filecategory")
        data = {
            "name": "",
            "description": "",
            "file_paths": [],
            "exclude_paths": [],
            "file_paths_queries": [],
            "access_monitoring": None,
        }
        response = self.post_json_data(reverse("osquery_api:file_categories"), data=data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "name": ["This field may not be blank."],
            "access_monitoring": ["This field may not be null."],
        })

    def test_create_file_category(self):
        self.set_permissions("osquery.add_filecategory")
        data = {
            "name": "file category name",
            "file_paths": ['/home/yo/bin'],
            "exclude_paths": ['/home/you/exclude', '/home/me/exclude'],
            "description": "description of the example file category",
            "file_paths_queries": ['select * from file_paths where path like "/home/yo/*.bin";'],
        }
        response = self.post_json_data(reverse("osquery_api:file_categories"), data=data)
        file_category = FileCategory.objects.first()
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json(), {
            "name": "file category name",
            "slug": slugify("file category name"),
            "id": file_category.id,
            "file_paths": ['/home/yo/bin'],
            "exclude_paths": ['/home/you/exclude', '/home/me/exclude'],
            "access_monitoring": False,
            "description": "description of the example file category",
            "file_paths_queries": ['select * from file_paths where path like "/home/yo/*.bin";'],
            "updated_at": file_category.updated_at.isoformat(),
            "created_at": file_category.created_at.isoformat(),
        })
        self.assertEqual(file_category.name, "file category name")
        self.assertEqual(file_category.slug, slugify("file category name"))
        self.assertEqual(file_category.file_paths, ['/home/yo/bin'])
        self.assertEqual(file_category.exclude_paths, ['/home/you/exclude', '/home/me/exclude'])
        self.assertEqual(file_category.access_monitoring, False)
        self.assertEqual(file_category.description, "description of the example file category")
        self.assertEqual(file_category.file_paths_queries,
                         ['select * from file_paths where path like "/home/yo/*.bin";'])

    # delete file category

    def test_delete_file_category_unauthorized(self):
        response = self.delete(reverse("osquery_api:file_category", args=[1]), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_file_category_permission_denied(self):
        response = self.delete(reverse("osquery_api:file_category", args=[1]))
        self.assertEqual(response.status_code, 403)

    def test_delete_file_category_not_found(self):
        self.set_permissions("osquery.delete_filecategory")
        response = self.delete(reverse("osquery_api:file_category", args=[9999]))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {
            "detail": "Not found."
        })

    def test_delete_file_category(self):
        file_category = self.force_file_category()
        self.set_permissions("osquery.delete_filecategory")
        response = self.delete(reverse("osquery_api:file_category", args=[file_category.id]))
        self.assertEqual(response.status_code, 204)
        self.assertEqual(FileCategory.objects.count(), 0)

    # list configurations

    def test_get_configurations_unauthorized(self):
        response = self.get(reverse("osquery_api:configurations"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_configurations_permission_denied(self):
        response = self.get(reverse("osquery_api:configurations"))
        self.assertEqual(response.status_code, 403)

    def test_get_configurations_filter_by_name_not_found(self):
        self.set_permissions("osquery.view_configuration")
        response = self.get(reverse("osquery_api:configurations"), {"name": get_random_string(32)})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])

    def test_get_configurations_filter_by_name(self):
        for _ in range(3):
            self.force_configuration()
        configuration = self.force_configuration()
        self.set_permissions("osquery.view_configuration")
        response = self.get(reverse("osquery_api:configurations"), {"name": configuration.name})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            "id": configuration.id,
            "name": configuration.name,
            "description": "",
            "inventory": True,
            "inventory_apps": False,
            "inventory_interval": 86400,
            "inventory_ec2": False,
            "file_categories": [],
            "automatic_table_constructions": [],
            "options": {},
            "created_at": configuration.created_at.isoformat(),
            "updated_at": configuration.updated_at.isoformat()
        }])

    def test_get_configurations(self):
        configuration = self.force_configuration()
        self.set_permissions("osquery.view_configuration")
        response = self.get(reverse('osquery_api:configurations'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, [{
            "id": configuration.pk,
            "name": configuration.name,
            'description': "",
            "inventory": True,
            "inventory_apps": False,
            "inventory_interval": 86400,
            "inventory_ec2": False,
            "file_categories": [],
            "automatic_table_constructions": [],
            "options": {},
            "created_at": configuration.created_at.isoformat(),
            "updated_at": configuration.updated_at.isoformat()
        }])

    # get configuration

    def test_get_configuration_unauthorized(self):
        configuration = self.force_configuration()
        response = self.get(reverse("osquery_api:configuration", args=(configuration.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_configuration_permission_denied(self):
        configuration = self.force_configuration()
        response = self.get(reverse("osquery_api:configuration", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_configuration_not_found(self):
        self.set_permissions("osquery.view_configuration")
        response = self.get(reverse("osquery_api:configuration", args=(9999,)))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {
            "detail": "Not found."
        })

    def test_get_configuration(self):
        configuration = self.force_configuration()
        self.set_permissions("osquery.view_configuration")
        response = self.get(reverse('osquery_api:configuration', args=(configuration.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertDictEqual(
            response.json(),
            {'id': configuration.pk,
             'name': configuration.name,
             'description': "",
             "inventory": True,
             "inventory_apps": False,
             "inventory_interval": 86400,
             "inventory_ec2": False,
             "file_categories": [],
             "automatic_table_constructions": [],
             "options": {},
             "created_at": configuration.created_at.isoformat(),
             "updated_at": configuration.updated_at.isoformat()}
        )

    # create configuration

    def test_create_configuration_unauthorized(self):
        response = self.post_json_data(reverse('osquery_api:configurations'), {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_create_configuration_permission_denied(self):
        response = self.post_json_data(reverse('osquery_api:configurations'), {})
        self.assertEqual(response.status_code, 403)

    def test_create_configuration_name_conflict(self):
        configuration = self.force_configuration()
        self.set_permissions("osquery.add_configuration")
        response = self.post_json_data(reverse('osquery_api:configurations'), {'name': configuration.name})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "name": ["configuration with this name already exists."]
        })

    def test_create_configuration_fields_empty(self):
        self.set_permissions("osquery.add_configuration")
        response = self.post_json_data(reverse('osquery_api:configurations'), {})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "name": ["This field is required."]
        })

    def test_create_configuration_atc_not_found(self):
        self.set_permissions("osquery.add_configuration")
        response = self.post_json_data(reverse('osquery_api:configurations'), {
            'name': 'Configuration0',
            'automatic_table_constructions': [9999]
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "automatic_table_constructions": ['Invalid pk "9999" - object does not exist.']
        })

    def test_create_configuration_file_category_not_found(self):
        self.set_permissions("osquery.add_configuration")
        response = self.post_json_data(reverse('osquery_api:configurations'), {
            'name': 'Configuration0',
            'file_categories': [9999]
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "file_categories": ['Invalid pk "9999" - object does not exist.']
        })

    def test_create_configuration(self):
        atc = self.force_atc()
        file_category = self.force_file_category()
        self.set_permissions("osquery.add_configuration")
        data = {
            'name': 'Configuration0',
            'description': 'Description0',
            'inventory': True,
            'inventory_apps': True,
            'inventory_interval': 3600,
            'inventory_ec2': True,
            'automatic_table_constructions': [atc.pk],
            'file_categories': [file_category.pk],
            'options': {
                'foo': 'bar'
            }
        }
        response = self.post_json_data(reverse('osquery_api:configurations'), data)
        self.assertEqual(response.status_code, 201)
        configuration = Configuration.objects.get(name="Configuration0")
        self.assertEqual(response.json(), {
            'id': configuration.pk,
            'name': 'Configuration0',
            'description': 'Description0',
            'inventory': True,
            'inventory_apps': True,
            'inventory_interval': 3600,
            'inventory_ec2': True,
            'automatic_table_constructions': [atc.pk],
            'file_categories': [file_category.pk],
            'options': {
                'foo': 'bar'
            },
            'created_at': configuration.created_at.isoformat(),
            'updated_at': configuration.updated_at.isoformat()
        })
        self.assertEqual(configuration.name, 'Configuration0')
        self.assertEqual(configuration.description, 'Description0')
        self.assertEqual(configuration.inventory, True)
        self.assertEqual(configuration.inventory_apps, True)
        self.assertEqual(configuration.inventory_interval, 3600)
        self.assertEqual(configuration.inventory_ec2, True)
        self.assertEqual(configuration.automatic_table_constructions.all()[0], atc)
        self.assertEqual(configuration.file_categories.all()[0], file_category)
        self.assertEqual(configuration.options, {'foo': 'bar'})

    # update configuration

    def test_update_configuration_unauthorized(self):
        response = self.put_json_data(reverse('osquery_api:configuration', args=(1,)), {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_update_configuration_permission_denied(self):
        response = self.put_json_data(reverse('osquery_api:configuration', args=(1,)), {})
        self.assertEqual(response.status_code, 403)

    def test_update_configuration_name_conflict(self):
        configuration = self.force_configuration()
        configuration2 = self.force_configuration()
        data = {'name': configuration.name}
        self.set_permissions("osquery.change_configuration")
        response = self.put_json_data(reverse('osquery_api:configuration', args=(configuration2.pk,)), data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "name": ["configuration with this name already exists."]
        })

    def test_update_configuration_fields_empty(self):
        configuration = self.force_configuration()
        self.set_permissions("osquery.change_configuration")
        response = self.put_json_data(reverse('osquery_api:configuration', args=(configuration.pk,)), {})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "name": ["This field is required."]
        })

    def test_update_configuration_not_found(self):
        self.set_permissions("osquery.change_configuration")
        response = self.put_json_data(reverse('osquery_api:configuration', args=(9999,)), {})
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {
            "detail": "Not found."
        })

    def test_update_configuration_atc_not_found(self):
        configuration = self.force_configuration()
        self.set_permissions("osquery.change_configuration")
        data = {
            'name': configuration.name,
            'automatic_table_constructions': [9999]
        }
        response = self.put_json_data(reverse('osquery_api:configuration', args=(configuration.id,)), data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "automatic_table_constructions": ['Invalid pk "9999" - object does not exist.']
        })

    def test_update_configuration_file_category_not_found(self):
        configuration = self.force_configuration()
        self.set_permissions("osquery.change_configuration")
        data = {
            'name': configuration.name,
            'file_categories': [9999]
        }
        response = self.put_json_data(reverse('osquery_api:configuration', args=(configuration.id,)), data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "file_categories": ['Invalid pk "9999" - object does not exist.']
        })

    def test_update_configuration_change_atc(self):
        configuration, _ = self.force_configuration(force_atc=True)
        atc = self.force_atc()
        self.set_permissions("osquery.change_configuration")
        data = {
            'name': configuration.name,
            'automatic_table_constructions': [atc.pk]
        }
        response = self.put_json_data(reverse('osquery_api:configuration', args=(configuration.id,)), data)
        self.assertEqual(response.status_code, 200)
        configuration.refresh_from_db()
        self.assertEqual(response.json(), {
            'id': configuration.pk,
            'name': configuration.name,
            'description': '',
            'inventory': True,
            'inventory_apps': False,
            'inventory_interval': 86400,
            'inventory_ec2': False,
            'automatic_table_constructions': [atc.pk],
            'file_categories': [],
            'options': {},
            'created_at': configuration.created_at.isoformat(),
            'updated_at': configuration.updated_at.isoformat()
        })
        self.assertEqual(configuration.automatic_table_constructions.all()[0], atc)

    def test_update_configuration_change_file_category(self):
        configuration, _ = self.force_configuration(force_file_category=True)
        file_category = self.force_file_category()
        self.set_permissions("osquery.change_configuration")
        data = {
            'name': configuration.name,
            'file_categories': [file_category.pk]
        }
        response = self.put_json_data(reverse('osquery_api:configuration', args=(configuration.id,)), data)
        self.assertEqual(response.status_code, 200)
        configuration.refresh_from_db()
        self.assertEqual(response.json(), {
            "id": configuration.pk,
            "name": configuration.name,
            "description": "",
            "inventory": True,
            "inventory_apps": False,
            "inventory_interval": 86400,
            "inventory_ec2": False,
            "automatic_table_constructions": [],
            "file_categories": [file_category.pk],
            "options": {},
            "created_at": configuration.created_at.isoformat(),
            "updated_at": configuration.updated_at.isoformat()
        })
        self.assertEqual(configuration.file_categories.all()[0], file_category)

    def test_update_configuration(self):
        configuration = self.force_configuration()
        new_name = get_random_string(12)
        atc = self.force_atc()
        file_category = self.force_file_category()
        data = {
            'name': new_name,
            'description': 'Description1',
            'inventory': True,
            'inventory_apps': True,
            'inventory_interval': 300,
            'inventory_ec2': True,
            'automatic_table_constructions': [atc.pk],
            'file_categories': [file_category.pk],
            'options': {
                'foo': 'bar'
            }
        }
        self.set_permissions("osquery.change_configuration")
        response = self.put_json_data(reverse('osquery_api:configuration', args=(configuration.pk,)), data)
        self.assertEqual(response.status_code, 200)
        configuration.refresh_from_db()
        self.assertEqual(response.json(), {
            "id": configuration.pk,
            "name": new_name,
            "description": "Description1",
            "inventory": True,
            "inventory_apps": True,
            "inventory_interval": 300,
            "inventory_ec2": True,
            "automatic_table_constructions": [atc.pk],
            "file_categories": [file_category.pk],
            "options": {"foo": "bar"},
            "created_at": configuration.created_at.isoformat(),
            "updated_at": configuration.updated_at.isoformat()
        })
        self.assertEqual(configuration.name, new_name)
        self.assertEqual(configuration.description, "Description1")
        self.assertEqual(configuration.inventory, True)
        self.assertEqual(configuration.inventory_apps, True)
        self.assertEqual(configuration.inventory_interval, 300)
        self.assertEqual(configuration.inventory_ec2, True)
        self.assertEqual(configuration.automatic_table_constructions.count(), 1)
        self.assertEqual(configuration.file_categories.count(), 1)
        self.assertEqual(configuration.options, {"foo": "bar"})

    # delete configuration

    def test_delete_configuration_unauthorized(self):
        response = self.delete(reverse('osquery_api:configuration', args=[1]), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_configuration_permission_denied(self):
        response = self.delete(reverse('osquery_api:configuration', args=[1]))
        self.assertEqual(response.status_code, 403)

    def test_delete_configuration_not_found(self):
        self.set_permissions("osquery.delete_configuration")
        response = self.delete(reverse('osquery_api:configuration', args=(9999,)))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {
            "detail": "Not found."
        })

    def test_delete_configuration_cannot_delete(self):
        configuration = self.force_configuration()
        enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=self.mbu)
        Enrollment.objects.create(configuration=configuration, secret=enrollment_secret)
        self.set_permissions("osquery.delete_configuration")
        response = self.delete(reverse('osquery_api:configuration', args=(configuration.pk,)))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), ["This configuration cannot be deleted"])

    def test_delete_configuration(self):
        configuration = self.force_configuration()
        self.set_permissions("osquery.delete_configuration")
        response = self.delete(reverse('osquery_api:configuration', args=(configuration.pk,)))
        self.assertEqual(response.status_code, 204)

    # list enrollments

    def test_get_enrollments_unauthorized(self):
        response = self.get(reverse("osquery_api:enrollments"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_enrollments_permission_denied(self):
        response = self.get(reverse("osquery_api:enrollments"))
        self.assertEqual(response.status_code, 403)

    def test_get_enrollments(self):
        enrollment, tags = self.force_enrollment(tag_count=1)
        self.set_permissions("osquery.view_enrollment")
        response = self.get(reverse('osquery_api:enrollments'))
        self.assertEqual(response.status_code, 200)
        fqdn = settings["api"]["fqdn"]
        self.assertIn(
            {'id': enrollment.pk,
             'configuration': enrollment.configuration.pk,
             'enrolled_machines_count': 0,
             'osquery_release': '',
             'secret': {
                 'id': enrollment.secret.pk,
                 'secret': enrollment.secret.secret,
                 'meta_business_unit': self.mbu.pk,
                 'tags': [tags[0].pk],
                 'serial_numbers': None,
                 'udids': None,
                 'quota': None,
                 'request_count': 0
             },
             'version': 1,
             'package_download_url': f'https://{fqdn}/api/osquery/enrollments/{enrollment.pk}/package/',
             'powershell_script_download_url': f'https://{fqdn}/api/osquery/'
                                               f'enrollments/{enrollment.pk}/powershell_script/',
             'script_download_url': f'https://{fqdn}/api/osquery/enrollments/{enrollment.pk}/script/',
             'created_at': enrollment.created_at.isoformat(),
             'updated_at': enrollment.updated_at.isoformat()},
            response.json()
        )

    # get enrollment

    def test_get_enrollment_unauthorized(self):
        response = self.get(reverse("osquery_api:enrollment", args=(1213028133,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_enrollment_permission_denied(self):
        response = self.get(reverse("osquery_api:enrollment", args=(1213028133,)))
        self.assertEqual(response.status_code, 403)

    def test_get_enrollment_not_found(self):
        self.set_permissions("osquery.view_enrollment")
        response = self.get(reverse("osquery_api:enrollment", args=(1213028133,)))
        self.assertEqual(response.status_code, 404)

    def test_get_enrollment(self):
        self.set_permissions("osquery.view_enrollment")
        enrollment, _ = self.force_enrollment()
        response = self.get(reverse("osquery_api:enrollment", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        fqdn = settings["api"]["fqdn"]
        self.assertEqual(
            response.json(),
            {'id': enrollment.pk,
             'configuration': enrollment.configuration.pk,
             'enrolled_machines_count': 0,
             'osquery_release': '',
             'secret': {
                 'id': enrollment.secret.pk,
                 'secret': enrollment.secret.secret,
                 'meta_business_unit': self.mbu.pk,
                 'tags': [],
                 'serial_numbers': None,
                 'udids': None,
                 'quota': None,
                 'request_count': 0
             },
             'version': 1,
             'package_download_url': f'https://{fqdn}/api/osquery/enrollments/{enrollment.pk}/package/',
             'powershell_script_download_url': f'https://{fqdn}/api/osquery/'
                                               f'enrollments/{enrollment.pk}/powershell_script/',
             'script_download_url': f'https://{fqdn}/api/osquery/enrollments/{enrollment.pk}/script/',
             'created_at': enrollment.created_at.isoformat(),
             'updated_at': enrollment.updated_at.isoformat()},
        )

    # get enrollment package

    def test_get_enrollment_package_unauthorized(self):
        enrollment, _ = self.force_enrollment()
        response = self.get(reverse("osquery_api:enrollment_package", args=(enrollment.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_enrollment_package_token_permission_denied(self):
        enrollment, _ = self.force_enrollment()
        response = self.get(reverse("osquery_api:enrollment_package", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_enrollment_package_user_permission_denied(self):
        enrollment, _ = self.force_enrollment()
        self.login()
        response = self.client.get(reverse("osquery_api:enrollment_package", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_enrollment_package_not_found(self):
        self.force_enrollment()
        self.set_permissions("osquery.view_enrollment")
        response = self.get(reverse("osquery_api:enrollment_package", args=(1213028133,)))
        self.assertEqual(response.status_code, 404)

    def test_get_enrollment_package_token(self):
        enrollment, _ = self.force_enrollment()
        self.set_permissions("osquery.view_enrollment")
        response = self.get(reverse("osquery_api:enrollment_package", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], "application/octet-stream")
        self.assertEqual(response['Content-Disposition'], 'attachment; filename="zentral_osquery_enroll.pkg"')
        self.assertEqual(response['Last-Modified'], http_date(enrollment.updated_at.timestamp()))
        self.assertEqual(response['ETag'], f'W/"osquery.enrollment-{enrollment.pk}-1"')

    def test_get_enrollment_package_user(self):
        enrollment, _ = self.force_enrollment()
        self.login("osquery.view_enrollment")
        response = self.client.get(reverse("osquery_api:enrollment_package", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], "application/octet-stream")
        self.assertEqual(response['Content-Disposition'], 'attachment; filename="zentral_osquery_enroll.pkg"')
        self.assertEqual(response['Last-Modified'], http_date(enrollment.updated_at.timestamp()))
        self.assertEqual(response['ETag'], f'W/"osquery.enrollment-{enrollment.pk}-1"')

    def test_get_enrollment_package_user_not_modified_etag_header(self):
        enrollment, _ = self.force_enrollment()
        etag = f'W/"osquery.enrollment-{enrollment.pk}-1"'
        last_modified = http_date(enrollment.updated_at.timestamp())
        req_headers = {"HTTP_IF_NONE_MATCH": etag}
        self.login("osquery.view_enrollment")
        response = self.client.get(reverse("osquery_api:enrollment_package", args=(enrollment.pk,)), **req_headers)
        self.assertEqual(response.status_code, 304)
        self.assertEqual(response['Last-Modified'], last_modified)
        self.assertEqual(response['ETag'], etag)

    def test_get_enrollment_package_user_not_modified_if_modified_since_header(self):
        enrollment, _ = self.force_enrollment()
        etag = f'W/"osquery.enrollment-{enrollment.pk}-1"'
        last_modified = http_date(enrollment.updated_at.timestamp())
        req_headers = {"HTTP_IF_MODIFIED_SINCE": http_date(enrollment.updated_at.timestamp())}
        self.login("osquery.view_enrollment")
        response = self.client.get(reverse("osquery_api:enrollment_package", args=(enrollment.pk,)), **req_headers)
        self.assertEqual(response.status_code, 304)
        self.assertEqual(response['Last-Modified'], last_modified)
        self.assertEqual(response['ETag'], etag)

    def test_get_enrollment_package_user_not_modified_both_headers(self):
        enrollment, _ = self.force_enrollment()
        etag = f'W/"osquery.enrollment-{enrollment.pk}-1"'
        last_modified = http_date(enrollment.updated_at.timestamp())
        req_headers = {"HTTP_IF_NONE_MATCH": etag,
                       "HTTP_IF_MODIFIED_SINCE": http_date(enrollment.updated_at.timestamp())}
        self.login("osquery.view_enrollment")
        response = self.client.get(reverse("osquery_api:enrollment_package", args=(enrollment.pk,)), **req_headers)
        self.assertEqual(response.status_code, 304)
        self.assertEqual(response['Last-Modified'], last_modified)
        self.assertEqual(response['ETag'], etag)

    def test_get_enrollment_package_user_etag_mismatch(self):
        enrollment, _ = self.force_enrollment()
        etag = f'W/"osquery.enrollment-{enrollment.pk}-1"'
        last_modified = http_date(enrollment.updated_at.timestamp())
        req_headers = {"HTTP_IF_NONE_MATCH": "YOLO"}
        self.login("osquery.view_enrollment")
        response = self.client.get(reverse("osquery_api:enrollment_package", args=(enrollment.pk,)), **req_headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Last-Modified'], last_modified)
        self.assertEqual(response['ETag'], etag)

    def test_get_enrollment_package_user_if_modified_since_too_old(self):
        enrollment, _ = self.force_enrollment()
        etag = f'W/"osquery.enrollment-{enrollment.pk}-1"'
        last_modified = http_date(enrollment.updated_at.timestamp())
        req_headers = {"HTTP_IF_MODIFIED_SINCE": http_date(datetime(2001, 1, 1).timestamp())}
        self.login("osquery.view_enrollment")
        response = self.client.get(reverse("osquery_api:enrollment_package", args=(enrollment.pk,)), **req_headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Last-Modified'], last_modified)
        self.assertEqual(response['ETag'], etag)

    # get enrollment powershell script

    def test_get_enrollment_powershell_script_unauthorized(self):
        enrollment, _ = self.force_enrollment()
        response = self.get(reverse("osquery_api:enrollment_powershell_script", args=(enrollment.pk,)),
                            include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_enrollment_powershell_script_token_permission_denied(self):
        enrollment, _ = self.force_enrollment()
        response = self.get(reverse("osquery_api:enrollment_powershell_script", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_enrollment_powershell_script_user_permission_denied(self):
        enrollment, _ = self.force_enrollment()
        self.login()
        response = self.client.get(reverse("osquery_api:enrollment_powershell_script", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_enrollment_powershell_script_not_found(self):
        self.force_enrollment()
        self.set_permissions("osquery.view_enrollment")
        response = self.get(reverse("osquery_api:enrollment_powershell_script", args=(1213028133,)))
        self.assertEqual(response.status_code, 404)

    def test_get_enrollment_powershell_script_token(self):
        enrollment, _ = self.force_enrollment()
        self.set_permissions("osquery.view_enrollment")
        response = self.get(reverse("osquery_api:enrollment_powershell_script", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], "text/plain")
        self.assertEqual(response['Content-Disposition'], 'attachment; filename="zentral_osquery_setup.ps1"')

    def test_get_enrollment_powershell_script_user(self):
        enrollment, _ = self.force_enrollment()
        self.login("osquery.view_enrollment")
        response = self.client.get(reverse("osquery_api:enrollment_powershell_script", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], "text/plain")
        self.assertEqual(response['Content-Disposition'], 'attachment; filename="zentral_osquery_setup.ps1"')

    # get enrollment script

    def test_get_enrollment_script_unauthorized(self):
        enrollment, _ = self.force_enrollment()
        response = self.get(reverse("osquery_api:enrollment_script", args=(enrollment.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_enrollment_script_token_permission_denied(self):
        enrollment, _ = self.force_enrollment()
        response = self.get(reverse("osquery_api:enrollment_script", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_enrollment_script_user_permission_denied(self):
        enrollment, _ = self.force_enrollment()
        self.login()
        response = self.client.get(reverse("osquery_api:enrollment_script", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_enrollment_script_not_found(self):
        self.force_enrollment()
        self.set_permissions("osquery.view_enrollment")
        response = self.get(reverse("osquery_api:enrollment_script", args=(1213028133,)))
        self.assertEqual(response.status_code, 404)

    def test_get_enrollment_script_token(self):
        enrollment, _ = self.force_enrollment()
        self.set_permissions("osquery.view_enrollment")
        response = self.get(reverse("osquery_api:enrollment_script", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], "text/x-shellscript")
        self.assertEqual(response['Content-Disposition'], 'attachment; filename="zentral_osquery_setup.sh"')

    def test_get_enrollment_script_user(self):
        enrollment, _ = self.force_enrollment()
        self.login("osquery.view_enrollment")
        response = self.client.get(reverse("osquery_api:enrollment_script", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], "text/x-shellscript")
        self.assertEqual(response['Content-Disposition'], 'attachment; filename="zentral_osquery_setup.sh"')

    # create enrollment

    def test_create_enrollment(self):
        config = self.force_configuration()
        self.set_permissions("osquery.add_enrollment")
        tags = [Tag.objects.create(name=get_random_string(12)) for _ in range(2)]
        response = self.post_json_data(
            reverse('osquery_api:enrollments'),
            {'configuration': config.pk,
             'secret': {"meta_business_unit": self.mbu.pk,
                        "tags": [t.id for t in tags]}}
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(Enrollment.objects.filter(configuration__name=config.name).count(), 1)
        enrollment = Enrollment.objects.get(configuration__name=config.name)
        self.assertEqual(enrollment.secret.meta_business_unit, self.mbu)
        self.assertEqual(
            set(enrollment.secret.tags.all()),
            set(tags)
        )

    # update enrollment

    def test_update_enrollment(self):
        enrollment, _ = self.force_enrollment(tag_count=2)
        enrollment_secret = enrollment.secret
        self.assertEqual(enrollment.osquery_release, "")
        self.assertEqual(enrollment.secret.quota, None)
        self.assertEqual(enrollment.secret.serial_numbers, None)
        self.assertEqual(enrollment.secret.tags.count(), 2)
        new_osquery_release = get_random_string(12)
        secret_data = EnrollmentSecretSerializer(enrollment_secret).data
        secret_data["id"] = 233333  # to check that there is no enrollment secret creation
        secret_data["quota"] = 23
        secret_data["request_count"] = 2331983  # to check that it cannot be updated
        tags = [Tag.objects.create(name=get_random_string(12)) for _ in range(2)]
        secret_data["tags"] = [t.id for t in tags]
        serial_numbers = [get_random_string(12) for i in range(13)]
        secret_data["serial_numbers"] = serial_numbers
        data = {"configuration": enrollment.configuration.pk,
                "osquery_release": new_osquery_release,
                "secret": secret_data}
        self.set_permissions("osquery.change_enrollment")
        response = self.put_json_data(reverse('osquery_api:enrollment', args=(enrollment.pk,)), data)
        self.assertEqual(response.status_code, 200)
        enrollment.refresh_from_db()
        self.assertEqual(enrollment.osquery_release, new_osquery_release)
        self.assertEqual(enrollment.secret, enrollment_secret)
        self.assertEqual(enrollment.secret.quota, 23)
        self.assertEqual(enrollment.secret.request_count, 0)
        self.assertEqual(enrollment.secret.serial_numbers, serial_numbers)
        self.assertEqual(
            set(enrollment.secret.tags.all()),
            set(tags)
        )

    # delete enrollment

    def test_delete_enrollment(self):
        enrollment, _ = self.force_enrollment()
        self.set_permissions("osquery.delete_enrollment")
        response = self.delete(reverse('osquery_api:enrollment', args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 204)

    # list packs

    def test_get_packs_unauthorized(self):
        response = self.get(reverse("osquery_api:packs"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_packs_permission_denied(self):
        response = self.get(reverse("osquery_api:packs"))
        self.assertEqual(response.status_code, 403)

    def test_get_packs_filter_by_name_not_found(self):
        self.set_permissions("osquery.view_pack")
        response = self.get(reverse("osquery_api:packs"), {"name": get_random_string(12)})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])

    def test_get_packs_filter_by_configuration_id_not_found(self):
        self.set_permissions("osquery.view_pack")
        response = self.get(reverse("osquery_api:packs"), {"configuration_id": 9999})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {"configuration_id": ["Select a valid choice. That choice is not one of the available choices."]}
        )

    def test_get_packs_filter_by_configuration_id_no_pack(self):
        self.set_permissions("osquery.view_pack")
        configuration = self.force_configuration()
        response = self.get(reverse("osquery_api:packs"), {"configuration_id": configuration.pk})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])

    def test_get_packs_filter_by_name(self):
        for _ in range(3):
            self.force_pack()
        pack = self.force_pack()
        self.set_permissions("osquery.view_pack")
        response = self.get(reverse("osquery_api:packs"), {"name": pack.name})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            "id": pack.pk,
            "name": pack.name,
            "slug": slugify(pack.name),
            "description": "",
            "discovery_queries": [],
            "shard": None,
            "event_routing_key": "",
            "created_at": pack.created_at.isoformat(),
            "updated_at": pack.updated_at.isoformat()
        }])

    def test_get_packs_filter_by_configuration_id(self):
        for _ in range(3):
            self.force_configuration(force_pack=True)
        configuration, pack, _ = self.force_configuration(force_pack=True)
        self.set_permissions("osquery.view_pack")
        response = self.get(reverse("osquery_api:packs"), {"configuration_id": configuration.pk})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            "id": pack.pk,
            "name": pack.name,
            "slug": slugify(pack.name),
            "description": "",
            "discovery_queries": [],
            "shard": None,
            "event_routing_key": "",
            "created_at": pack.created_at.isoformat(),
            "updated_at": pack.updated_at.isoformat()
        }])

    def test_get_packs(self):
        pack = self.force_pack()
        self.set_permissions("osquery.view_pack")
        response = self.get(reverse("osquery_api:packs"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            "id": pack.pk,
            "name": pack.name,
            "slug": slugify(pack.name),
            "description": "",
            "discovery_queries": [],
            "shard": None,
            "event_routing_key": "",
            "created_at": pack.created_at.isoformat(),
            "updated_at": pack.updated_at.isoformat()
        }])

    # get pack <int:pk>

    def test_get_pack_unauthorized(self):
        response = self.get(reverse("osquery_api:pack", args=(1,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_pack_permission_denied(self):
        response = self.get(reverse("osquery_api:pack", args=(1,)))
        self.assertEqual(response.status_code, 403)

    def test_get_pack_not_found(self):
        self.set_permissions("osquery.view_pack")
        response = self.get(reverse("osquery_api:pack", args=(9999,)))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {
            "detail": "Not found."
        })

    def test_get_pack(self):
        self.set_permissions("osquery.view_pack")
        pack = self.force_pack()
        response = self.get(reverse("osquery_api:pack", args=(pack.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            "id": pack.pk,
            "name": pack.name,
            "slug": slugify(pack.name),
            "description": "",
            "discovery_queries": [],
            "shard": None,
            "event_routing_key": "",
            "created_at": pack.created_at.isoformat(),
            "updated_at": pack.updated_at.isoformat()
        })

    # update pack <int:pk>

    def test_update_pack_unauthorized(self):
        response = self.put_json_data(reverse("osquery_api:pack", args=(1,)), {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_update_pack_permission_denied(self):
        response = self.put_json_data(reverse("osquery_api:pack", args=(1,)), {})
        self.assertEqual(response.status_code, 403)

    def test_update_pack_not_found(self):
        self.set_permissions("osquery.change_pack")
        response = self.put_json_data(reverse("osquery_api:pack", args=(9999,)), {})
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {
            "detail": "Not found."
        })

    def test_update_pack_slug_conflict(self):
        pack = self.force_pack()
        pack2 = self.force_pack()
        self.set_permissions("osquery.change_pack")
        data = {"name": pack.name.upper()}
        response = self.put_json_data(reverse("osquery_api:pack", args=(pack2.pk,)), data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "name": [f"Pack with this slug {pack.slug} already exists"]
        })

    def test_update_pack_slug_not_editable(self):
        pack = self.force_pack()
        pack_name = "Packed"
        new_slug = slugify(get_random_string(45))
        self.set_permissions("osquery.change_pack")
        data = {
            "name": pack_name,
            "slug": new_slug
        }
        response = self.put_json_data(reverse("osquery_api:pack", args=(pack.pk,)), data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["slug"], 'packed')

    def test_update_pack_name_conflict(self):
        pack = self.force_pack()
        pack2 = self.force_pack()
        self.set_permissions("osquery.change_pack")
        data = {"name": pack.name}
        response = self.put_json_data(reverse("osquery_api:pack", args=(pack2.pk,)), data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "name": ["pack with this name already exists."]
        })

    def test_update_pack_fields_empty(self):
        pack = self.force_pack()
        self.set_permissions("osquery.change_pack")
        data = {"name": ""}
        response = self.put_json_data(reverse("osquery_api:pack", args=(pack.pk,)), data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "name": ["This field may not be blank."]
        })

    def test_update_pack_shard_invalid(self):
        pack = self.force_pack()
        self.set_permissions("osquery.change_pack")
        data = {
            "name": pack.name,
            "shard": 101
        }
        response = self.put_json_data(reverse("osquery_api:pack", args=(pack.pk,)), data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "shard": ["Ensure this value is less than or equal to 100."]
        })

    def test_update_pack(self):
        pack = self.force_pack()
        self.set_permissions("osquery.change_pack")
        data = {
            "name": "pack updated",
            "description": "pack description updated",
            "discovery_queries": ["select * from osquery_info"],
            "shard": 1,
            "event_routing_key": "pack_updated"
        }
        response = self.put_json_data(reverse("osquery_api:pack", args=(pack.pk,)), data)
        self.assertEqual(response.status_code, 200)
        pack.refresh_from_db()
        self.assertEqual(response.json(), {
            "id": pack.pk,
            "name": "pack updated",
            "slug": "pack-updated",
            "description": "pack description updated",
            "discovery_queries": ["select * from osquery_info"],
            "shard": 1,
            "event_routing_key": "pack_updated",
            "created_at": pack.created_at.isoformat(),
            "updated_at": pack.updated_at.isoformat()
        })
        self.assertEqual(pack.name, "pack updated")
        self.assertEqual(pack.slug, "pack-updated")
        self.assertEqual(pack.description, "pack description updated")
        self.assertEqual(pack.discovery_queries, ["select * from osquery_info"])
        self.assertEqual(pack.shard, 1)
        self.assertEqual(pack.event_routing_key, "pack_updated")

    # create pack

    def test_create_pack_unauthorized(self):
        response = self.post_json_data(reverse("osquery_api:packs"), {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_create_pack_permission_denied(self):
        response = self.post_json_data(reverse("osquery_api:packs"), {})
        self.assertEqual(response.status_code, 403)

    def test_create_pack_fields_empty(self):
        self.set_permissions("osquery.add_pack")
        data = {"name": ""}
        response = self.post_json_data(reverse("osquery_api:packs"), data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "name": ["This field may not be blank."]
        })

    def test_create_pack_name_conflict(self):
        pack = self.force_pack()
        self.set_permissions("osquery.add_pack")
        data = {"name": pack.name}
        response = self.post_json_data(reverse("osquery_api:packs"), data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "name": ["pack with this name already exists."]
        })

    def test_create_pack_slug_conflict(self):
        pack = self.force_pack()
        self.set_permissions("osquery.add_pack")
        data = {"name": pack.name.upper()}
        response = self.post_json_data(reverse("osquery_api:packs"), data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "name": [f"Pack with this slug {pack.slug} already exists"]
        })

    def test_create_pack_slug_not_editable(self):
        self.set_permissions("osquery.add_pack")
        data = {"name": "pack created", "slug": "slug-created"}
        response = self.post_json_data(reverse("osquery_api:packs"), data)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["slug"], "pack-created")

    def test_create_pack_shard_invalid(self):
        self.set_permissions("osquery.add_pack")
        data = {"name": "pack created", "shard": 101}
        response = self.post_json_data(reverse("osquery_api:packs"), data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "shard": ["Ensure this value is less than or equal to 100."]
        })

    def test_create_pack(self):
        self.set_permissions("osquery.add_pack")
        data = {
            "name": "pack created",
            "description": "pack description created",
            "discovery_queries": ["select * from osquery_info"],
            "shard": 1,
            "event_routing_key": "pack_created"
        }
        response = self.post_json_data(reverse("osquery_api:packs"), data)
        self.assertEqual(response.status_code, 201)
        pack = Pack.objects.first()
        self.assertEqual(response.json(), {
            "id": pack.pk,
            "name": "pack created",
            "slug": "pack-created",
            "description": "pack description created",
            "discovery_queries": ["select * from osquery_info"],
            "shard": 1,
            "event_routing_key": "pack_created",
            "created_at": pack.created_at.isoformat(),
            "updated_at": pack.updated_at.isoformat()
        })
        self.assertEqual(pack.name, "pack created")
        self.assertEqual(pack.slug, "pack-created")
        self.assertEqual(pack.description, "pack description created")
        self.assertEqual(pack.discovery_queries, ["select * from osquery_info"])
        self.assertEqual(pack.shard, 1)
        self.assertEqual(pack.event_routing_key, "pack_created")

    # delete pack <int:pk>

    def test_delete_pack_unauthorized_by_pk(self):
        response = self.delete(reverse("osquery_api:pack", args=(1,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_pack_permission_denied_by_pk(self):
        response = self.delete(reverse("osquery_api:pack", args=(1,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_pack_not_found_by_pk(self):
        self.set_permissions("osquery.delete_pack")
        response = self.delete(reverse("osquery_api:pack", args=(9999,)))
        self.assertEqual(response.status_code, 404)

    def test_delete_pack_by_pk(self):
        self.set_permissions("osquery.delete_pack")
        pack = self.force_pack()
        response = self.delete(reverse("osquery_api:pack", args=(pack.pk,)))
        self.assertEqual(response.status_code, 204)
        self.assertFalse(Pack.objects.filter(pk=pack.pk).exists())

    # put pack <slug:slug>

    def test_put_pack_unauthorized(self):
        url = reverse("osquery_api:pack", args=(get_random_string(12),))
        response = self.put_json_data(url, {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_put_pack_permission_denied(self):
        url = reverse("osquery_api:pack", args=(get_random_string(12),))
        response = self.put_json_data(url, {}, include_token=True)
        self.assertEqual(response.status_code, 403)

    # delete pack <slug:slug>

    def test_delete_pack_unauthorized(self):
        url = reverse("osquery_api:pack", args=(get_random_string(12),))
        response = self.delete(url, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_pack_permission_denied(self):
        url = reverse("osquery_api:pack", args=(get_random_string(12),))
        response = self.delete(url, include_token=True)
        self.assertEqual(response.status_code, 403)

    def test_put_no_queries(self):
        self.set_pack_endpoint_put_permissions()
        url = reverse("osquery_api:pack", args=(get_random_string(12),))
        response = self.put_json_data(url, {})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'queries': ['This field is required.']}
        )

    def test_put_malformed_query(self):
        self.set_pack_endpoint_put_permissions()
        url = reverse("osquery_api:pack", args=(get_random_string(12),))
        response = self.put_json_data(url, {"queries": {"first_query": {"query": ""}}})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'queries': {'first_query': {'interval': ['This field is required.'],
                                         'query': ['This field may not be blank.']}}}
        )

    def test_put_removed_and_snapshot_query(self):
        self.set_pack_endpoint_put_permissions()
        url = reverse("osquery_api:pack", args=(get_random_string(12),))
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

    def test_put_diff_query_with_compliance_check(self):
        self.set_pack_endpoint_put_permissions()
        url = reverse("osquery_api:pack", args=(get_random_string(12),))
        response = self.put_json_data(
            url,
            {"queries": {"first_query": {"query": "select 'OK' as ztl_status",
                                         "interval": 10,
                                         "removed": True,
                                         "snapshot": False,
                                         "compliance_check": True}}},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'queries': {
                'first_query': {
                    'non_field_errors': [
                        '{"compliance_check": true} only available in "snapshot" mode']
                }
            }}
        )

    def test_put_query_with_compliance_check_without_ztl_status(self):
        self.set_pack_endpoint_put_permissions()
        url = reverse("osquery_api:pack", args=(get_random_string(12),))
        response = self.put_json_data(
            url,
            {"queries": {"first_query": {"query": "select * from users",
                                         "interval": 10,
                                         "snapshot": True,
                                         "compliance_check": True}}},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'queries': {
                'first_query': {
                    'non_field_errors': [
                        '{"compliance_check": true} only if query contains "ztl_status"']
                }
            }}
        )

    def test_put_invalid_version_query(self):
        self.set_pack_endpoint_put_permissions()
        url = reverse("osquery_api:pack", args=(get_random_string(12),))
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
        url = reverse("osquery_api:pack", args=(get_random_string(12),))
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
        url = reverse("osquery_api:pack", args=(get_random_string(12),))
        response = self.put_json_data(
            url,
            {"queries": {"first_query": {"query": "select * from users;",
                                         "interval": 10920092820982}}},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'queries': {'first_query': {'interval': ['Ensure this value is less than or equal to 604800.']}}}
        )

    def test_put_invalid_shard_query(self):
        self.set_pack_endpoint_put_permissions()
        url = reverse("osquery_api:pack", args=(get_random_string(12),))
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
        Pack.objects.create(slug=get_random_string(12), name="Yolo")
        url = reverse("osquery_api:pack", args=(get_random_string(12),))
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

    def test_put_empty_query_name(self):
        self.set_pack_endpoint_put_permissions()
        url = reverse("osquery_api:pack", args=(get_random_string(12),))
        response = self.put_json_data(
            url,
            {"name": "Yolo",
             "queries": {"": {"query": "select 1 from users;",
                              "interval": 10}}}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {"queries": ["Query name cannot be empty"]}
        )

    def test_put_pack_json(self):
        self.set_pack_endpoint_put_permissions()
        slug = get_random_string(12)
        url = reverse("osquery_api:pack", args=(slug,))

        # create pack
        pack = {
            "platform": "posix",
            "version": "1.2.3",
            "discovery": [
                "select 1 from users where username='root'",
            ],
            "event_routing_key": "123ABC",
            "queries": {
                "Leverage-A_1": {
                    "query": "select * from launchd where path like '%UserEvent.System.plist';",
                    "interval": "3600",
                    "version": "1.4.9",
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
                    "query": "select 'OK' as ztl_status;",
                    "platform": "darwin",
                    "interval": 7200,
                    "snapshot": True,
                    "denylist": False,
                    "shard": 97,
                    "compliance_check": True
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
        self.assertEqual(p.event_routing_key, "123ABC")
        for pack_query in p.packquery_set.select_related("query").all():
            query = pack_query.query
            if pack_query.slug == "Leverage-A_1":
                self.assertEqual(query.platforms, ["posix"])
                self.assertEqual(query.minimum_osquery_version, "1.4.9")
                self.assertIsNone(query.compliance_check)
            elif pack_query.slug == "Leverage-A_2":
                self.assertEqual(query.platforms, ["posix"])
                self.assertEqual(query.minimum_osquery_version, "1.4.5")
                self.assertIsNone(query.compliance_check)
            elif pack_query.slug == "Snapshot1":
                self.assertEqual(query.platforms, ["darwin"])
                self.assertEqual(query.minimum_osquery_version, "1.2.3")
                self.assertEqual(query.compliance_check.name, query.name)
                self.assertEqual(query.compliance_check.version, query.version)
            else:
                raise AssertionError("Unknown plack slug")

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
        self.assertEqual(pack_query.query.compliance_check.version, 1)

        # update query
        pack["queries"]["Snapshot1"]["query"] = "select 'FAILED' as ztl_status;"
        response = self.put_json_data(url, pack)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'pack': {'pk': p.pk, 'slug': slug},
             'result': 'present',
             'query_results': {'created': 0, 'deleted': 0, 'present': 2, 'updated': 1}}
        )
        pack_query.refresh_from_db()
        self.assertEqual(pack_query.query.sql, "select 'FAILED' as ztl_status;")
        self.assertEqual(pack_query.query.version, 2)
        self.assertEqual(pack_query.query.compliance_check.version, 2)

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
        snapshot_1["query"] = "select 'OK' as ztl_status"
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
        self.assertEqual(query.sql, "select 'OK' as ztl_status")
        self.assertEqual(query.version, 3)
        self.assertEqual(query.compliance_check.version, 3)

    def test_put_pack_osquery_conf_parse_error(self):
        self.set_pack_endpoint_put_permissions()
        slug = get_random_string(12)
        url = reverse("osquery_api:pack", args=(slug,))

        pack = """
        {
          // Do not use this query in production!!!
        """

        response = self.put_data(url, pack.encode("utf-8"), "application/x-osquery-conf", include_token=True)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'detail': 'Osquery config parse error'})

    def test_put_pack_osquery_conf(self):
        self.set_pack_endpoint_put_permissions()
        slug = get_random_string(12)
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
        slug = get_random_string(12)
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
        slug = get_random_string(12)
        url = reverse("osquery_api:pack", args=(slug,))
        response = self.delete(url, include_token=True)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(
            response.json(),
            {"pack": {"slug": slug}, "result": "absent"}
        )

    def test_delete_pack(self):
        slug = get_random_string(12)
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

    # export distributed query results

    def _force_distributed_query(self):
        query = Query.objects.create(
            name=get_random_string(12),
            sql="select * from osquery_schedule;"
        )
        return DistributedQuery.objects.create(
            query=query,
            query_version=query.version,
            sql=query.sql,
            valid_from=datetime.utcnow(),
        )

    def test_export_distributed_query_results_401(self):
        dq = self._force_distributed_query()
        response = self.post(reverse("osquery_api:export_distributed_query_results", args=(dq.pk,)),
                             include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_export_distributed_query_results_403(self):
        dq = self._force_distributed_query()
        response = self.post(reverse("osquery_api:export_distributed_query_results", args=(dq.pk,)),
                             include_token=True)
        self.assertEqual(response.status_code, 403)

    def test_export_distributed_query_results_ok(self):
        dq = self._force_distributed_query()
        self.set_permissions("osquery.view_distributedqueryresult")
        response = self.post(reverse("osquery_api:export_distributed_query_results", args=(dq.pk,)),
                             include_token=True)
        self.assertEqual(response.status_code, 201)

    # list queries

    def test_get_queries(self):
        query = self.force_query()
        self.set_permissions("osquery.view_query")
        response = self.get(reverse("osquery_api:queries"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(),
                         [{"id": query.pk,
                           "name": query.name,
                           "version": 1,
                           "compliance_check_enabled": False,
                           "sql": query.sql,
                           "minimum_osquery_version": None,
                           "description": query.description,
                           "value": '',
                           "platforms": [],
                           "created_at": query.created_at.isoformat(),
                           "updated_at": query.updated_at.isoformat()
                           }])

    def test_get_queries_unauthorized(self):
        response = self.get(reverse("osquery_api:queries"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_queries_permission_denied(self):
        response = self.get(reverse("osquery_api:queries"))
        self.assertEqual(response.status_code, 403)

    def test_get_queries_filter_by_name(self):
        query = self.force_query()
        for _ in range(3):
            self.force_query()
        self.set_permissions("osquery.view_query")
        response = self.get(reverse("osquery_api:queries"), {"name": query.name})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(),
                         [{"id": query.pk,
                           "name": query.name,
                           "version": 1,
                           "compliance_check_enabled": False,
                           "sql": query.sql,
                           "minimum_osquery_version": None,
                           "description": query.description,
                           "value": '',
                           "platforms": [],
                           "created_at": query.created_at.isoformat(),
                           "updated_at": query.updated_at.isoformat()
                           }])

    # create queries

    def test_create_query(self):
        data = {
            "name": "test_query01",
            "sql": "select * from osquery_info;",
            "compliance_check_enabled": False
        }
        self.set_permissions("osquery.add_query")
        response = self.post_json_data(reverse("osquery_api:queries"), data)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(Query.objects.filter(name='test_query01').count(), 1)
        query = Query.objects.get(name='test_query01')
        self.assertEqual(response.json(),
                         {"id": query.pk,
                          "name": query.name,
                          "version": 1,
                          "compliance_check_enabled": False,
                          "sql": "select * from osquery_info;",
                          "minimum_osquery_version": None,
                          "description": "",
                          "value": '',
                          "platforms": [],
                          "created_at": query.created_at.isoformat(),
                          "updated_at": query.updated_at.isoformat()
                          })

    def test_create_query_ztl_status_validate_error(self):
        data = {
            "name": get_random_string(12),
            "sql": "select * from osquery_info;",
            "compliance_check_enabled": True
        }
        self.set_permissions("osquery.add_query")
        response = self.post_json_data(reverse("osquery_api:queries"), data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'compliance_check_enabled': ['ztl_status not in sql']})

    def test_create_query_ztl_status_validate_success(self):
        query_name = get_random_string(12)
        data = {
            "name": query_name,
            "sql": "ztl_status;",
            "compliance_check_enabled": True
        }
        self.set_permissions("osquery.add_query")
        response = self.post_json_data(reverse("osquery_api:queries"), data)
        query = Query.objects.get(name=query_name)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["compliance_check_enabled"], True)
        self.assertIs(isinstance(query.compliance_check, ComplianceCheck), True)
        self.assertEqual(query.sql, "ztl_status;")

    def test_create_query_unauthorized(self):
        data = {
            "name": "test_query01",
            "sql": "select * from osquery_info;"
        }
        response = self.post_json_data(reverse("osquery_api:queries"), data, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_create_query_permission_denied(self):
        data = {
            "name": "test_query01",
            "sql": "select * from osquery_info;"
        }
        response = self.post_json_data(reverse("osquery_api:queries"), data)
        self.assertEqual(response.status_code, 403)

    def test_create_query_with_platforms(self):
        name = get_random_string(12)
        data = {
            "name": name,
            "sql": "select * from osquery_info;",
            "platforms": [
                "darwin",
                "linux"
            ]
        }
        self.set_permissions("osquery.add_query")
        response = self.post_json_data(reverse("osquery_api:queries"), data)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["platforms"], ["darwin", "linux"])
        query = Query.objects.get(name=name)
        self.assertEqual(query.platforms, ["darwin", "linux"])
        self.assertEqual(len(query.platforms), 2)

    def test_create_query_with_unsupported_platform(self):
        name = get_random_string(12)
        data = {
            "name": name,
            "sql": "select * from osquery_info;",
            "platforms": ["haiku"]
        }
        self.set_permissions("osquery.add_query")
        response = self.post_json_data(reverse("osquery_api:queries"), data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'platforms': {'0': ['"haiku" is not a valid choice.']}})
        with self.assertRaises(Query.DoesNotExist):
            Query.objects.get(name=name)

    # get query

    def test_get_query(self):
        query = self.force_query()
        self.set_permissions("osquery.view_query")
        response = self.get(reverse("osquery_api:query", args=(query.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(),
                         {"id": query.pk,
                          "name": query.name,
                          "version": 1,
                          "compliance_check_enabled": False,
                          "sql": query.sql,
                          "minimum_osquery_version": None,
                          "description": query.description,
                          "value": '',
                          "platforms": [],
                          "created_at": query.created_at.isoformat(),
                          "updated_at": query.updated_at.isoformat()
                          })

    def test_get_query_compliance_check_enabled(self):
        query = self.force_query(compliance_check=True)
        self.set_permissions("osquery.view_query")
        response = self.get(reverse("osquery_api:query", args=(query.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["compliance_check_enabled"], True)
        self.assertIs(isinstance(query.compliance_check, ComplianceCheck), True)

    def test_get_query_unauthorized(self):
        query = self.force_query()
        response = self.get(reverse("osquery_api:query", args=(query.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_query_permission_denied(self):
        query = self.force_query()
        response = self.get(reverse("osquery_api:query", args=(query.pk,)))
        self.assertEqual(response.status_code, 403)

    # update query

    def test_update_query(self):
        query = self.force_query()
        new_name = get_random_string(12)
        data = {"name": new_name, "sql": query.sql}
        self.set_permissions("osquery.change_query")
        response = self.put_json_data(reverse("osquery_api:query", args=(query.pk,)), data)
        self.assertEqual(response.status_code, 200)
        query.refresh_from_db()
        self.assertEqual(Query.objects.filter(name=new_name).count(), 1)
        self.assertEqual(query.name, new_name)

    def test_update_query_unauthorized(self):
        query = self.force_query()
        new_name = get_random_string(12)
        data = {"name": new_name, "sql": query.sql}
        response = self.put_json_data(reverse("osquery_api:query", args=(query.pk,)), data, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_update_query_permission_denied(self):
        query = self.force_query()
        new_name = get_random_string(12)
        data = {"name": new_name, "sql": query.sql}
        response = self.put_json_data(reverse("osquery_api:query", args=(query.pk,)), data)
        self.assertEqual(response.status_code, 403)

    def test_update_query_ztl_status_validate_error(self):
        query = self.force_query()
        data = {"name": query.name, "sql": query.sql, "compliance_check_enabled": True}
        self.set_permissions("osquery.change_query")
        response = self.put_json_data(reverse("osquery_api:query", args=(query.pk,)), data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'compliance_check_enabled': ['ztl_status not in sql']})

    def test_update_query_ztl_status_validate_success(self):
        query = self.force_query()
        data = {"name": query.name, "sql": "ztl_status;", "compliance_check_enabled": True}
        self.set_permissions("osquery.change_query")
        response = self.put_json_data(reverse("osquery_api:query", args=(query.pk,)), data)
        query.refresh_from_db()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["compliance_check_enabled"], True)
        self.assertIs(isinstance(query.compliance_check, ComplianceCheck), True)
        self.assertEqual(query.sql, "ztl_status;")

    def test_update_query_increment_version(self):
        query = self.force_query()
        self.assertEqual(query.version, 1)
        new_sql = "changed sql line;"
        data = {"name": query.name, "sql": new_sql}
        self.set_permissions("osquery.change_query")
        response = self.put_json_data(reverse("osquery_api:query", args=(query.pk,)), data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["version"], 2)
        query.refresh_from_db()
        self.assertEqual(query.version, 2)
        self.assertEqual(query.sql, "changed sql line;")

    def test_update_query_with_pack_query_snapshot_mode_validate_success(self):
        query = self.force_query(pack_query_mode="snapshot", compliance_check=False)
        data = {"name": query.name, "sql": "select 'OK' as ztl_status;", "compliance_check_enabled": True}
        self.set_permissions("osquery.change_query")
        response = self.put_json_data(reverse("osquery_api:query", args=(query.pk,)), data)
        query.refresh_from_db()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["compliance_check_enabled"], True)
        self.assertEqual(query.sql, "select 'OK' as ztl_status;")
        self.assertIs(isinstance(query.compliance_check, ComplianceCheck), True)

    def test_update_query_with_pack_query_diff_mode_validation_error(self):
        query = self.force_query(pack_query_mode="diff", compliance_check=False)
        pack_query = PackQuery.objects.get(slug=slugify(query.name))
        data = {"name": query.name, "sql": "select 'OK' as ztl_status;", "compliance_check_enabled": True}
        self.set_permissions("osquery.change_query")
        response = self.put_json_data(reverse("osquery_api:query", args=(query.pk,)), data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'compliance_check_enabled': [f'query scheduled in diff mode in {pack_query.pack} pack']})

    def test_update_query_add_platforms(self):
        query = self.force_query()
        data = {
            "name": query.name,
            "sql": query.sql,
            "platforms": [
                "darwin",
                "freebsd",
                "linux",
                "posix",
                "windows"
            ]
        }
        self.set_permissions("osquery.change_query")
        response = self.put_json_data(reverse("osquery_api:query", args=(query.pk,)), data)
        self.assertEqual(response.status_code, 200)
        query.refresh_from_db()
        self.assertEqual(query.platforms, ["darwin", "freebsd", "linux", "posix", "windows"])
        self.assertEqual(len(query.platforms), 5)

    def test_update_query_add_unsupported_platform(self):
        query = self.force_query()
        data = {
            "name": query.name,
            "sql": query.sql,
            "platforms": ["beOS"]
        }
        self.set_permissions("osquery.change_query")
        response = self.put_json_data(reverse("osquery_api:query", args=(query.pk,)), data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'platforms': {'0': ['"beOS" is not a valid choice.']}})
        query.refresh_from_db()
        self.assertEqual(query.platforms, [])

    # delete query

    def test_delete_query(self):
        query = self.force_query()
        self.set_permissions("osquery.delete_query")
        response = self.delete(reverse("osquery_api:query", args=(query.pk,)))
        self.assertEqual(response.status_code, 204)
        self.assertEqual(Query.objects.filter(pk=query.pk).count(), 0)

    def test_delete_query_cannot_be_deleted(self):
        query = self.force_query(pack_query_mode="diff")
        self.set_permissions("osquery.delete_query")
        response = self.delete(reverse("osquery_api:query", args=(query.pk,)))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            [f"This query is included in pack {query.packquery.pack.pk}"]
        )

    def test_delete_query_unauthorized(self):
        query = self.force_query()
        response = self.delete(reverse("osquery_api:query", args=(query.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_query_permission_denied(self):
        query = self.force_query()
        response = self.delete(reverse("osquery_api:query", args=(query.pk,)))
        self.assertEqual(response.status_code, 403)

    # List ConfigurationPacks

    def test_list_configuration_packs_unauthorized(self):
        response = self.get(reverse("osquery_api:configuration_packs"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_list_configuration_packs_permission_denied(self):
        response = self.get(reverse("osquery_api:configuration_packs"))
        self.assertEqual(response.status_code, 403)

    def test_list_configuration_packs_filter_configuration_id_not_found(self):
        self.set_permissions("osquery.view_configurationpack")
        response = self.get(reverse("osquery_api:configuration_packs"), {"configuration_id": 9999})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            'configuration_id': ['Select a valid choice. That choice is not one of the available choices.']
        })

    def test_list_configuration_packs_filter_pack_id_not_found(self):
        self.set_permissions("osquery.view_configurationpack")
        response = self.get(reverse("osquery_api:configuration_packs"), {"pack_id": 9999})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            'pack_id': ['Select a valid choice. That choice is not one of the available choices.']
        })

    def test_list_configuration_packs_filter_configuration_id(self):
        self.set_permissions("osquery.view_configurationpack")
        for _ in range(3):
            self.force_configuration_pack()
        configuration, pack, configuration_pack = self.force_configuration(force_pack=True)
        response = self.get(reverse("osquery_api:configuration_packs"), {"configuration_id": configuration.pk})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            "id": configuration_pack.pk,
            "configuration": configuration.pk,
            "tags": [],
            "pack": pack.pk
        }])

    def test_list_configuration_packs_filter_pack_id(self):
        self.set_permissions("osquery.view_configurationpack")
        for _ in range(3):
            self.force_configuration_pack()
        configuration, pack, configuration_pack = self.force_configuration(force_pack=True)
        response = self.get(reverse("osquery_api:configuration_packs"), {"pack_id": pack.pk})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            "id": configuration_pack.pk,
            "configuration": configuration.pk,
            "tags": [],
            "pack": pack.pk
        }])

    def test_list_configuration_packs(self):
        self.set_permissions("osquery.view_configurationpack")
        configuration_pack = self.force_configuration_pack()
        response = self.get(reverse("osquery_api:configuration_packs"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            "id": configuration_pack.pk,
            "configuration": configuration_pack.configuration.pk,
            "tags": [],
            "pack": configuration_pack.pack.pk
        }])

    # get configuration pack

    def test_get_configuration_pack_unauthorized(self):
        response = self.get(reverse("osquery_api:configuration_pack", args=(9999,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_configuration_pack_permission_denied(self):
        response = self.get(reverse("osquery_api:configuration_pack", args=(9999,)))
        self.assertEqual(response.status_code, 403)

    def test_get_configuration_pack_not_found(self):
        self.set_permissions("osquery.view_configurationpack")
        response = self.get(reverse("osquery_api:configuration_pack", args=(9999,)))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {
            "detail": "Not found."
        })

    def test_get_configuration_pack(self):
        self.set_permissions("osquery.view_configurationpack")
        configuration_pack = self.force_configuration_pack(force_tags=True)
        response = self.get(reverse("osquery_api:configuration_pack", args=(configuration_pack.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            "id": configuration_pack.pk,
            "configuration": configuration_pack.configuration.pk,
            "tags": [t.id for t in configuration_pack.tags.all()],
            "pack": configuration_pack.pack.pk
        })

    # update configuration pack

    def test_update_configuration_pack_unauthorized(self):
        response = self.put_json_data(reverse("osquery_api:configuration_pack", args=(9999,)), {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_update_configuration_pack_permission_denied(self):
        response = self.put_json_data(reverse("osquery_api:configuration_pack", args=(9999,)), {})
        self.assertEqual(response.status_code, 403)

    def test_update_configuration_pack_not_found(self):
        self.set_permissions("osquery.change_configurationpack")
        response = self.put_json_data(reverse("osquery_api:configuration_pack", args=(9999,)), {})
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {
            "detail": "Not found."
        })

    def test_update_configuration_pack_configuration_fields_empty(self):
        self.set_permissions("osquery.change_configurationpack")
        configuration_pack = self.force_configuration_pack()
        response = self.put_json_data(reverse("osquery_api:configuration_pack", args=(configuration_pack.pk,)), {})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "configuration": ["This field is required."],
            "pack": ["This field is required."]
        })

    def test_update_configuration_pack_conflict(self):
        self.set_permissions("osquery.change_configurationpack")
        configuration_pack = self.force_configuration_pack()
        configuration_pack2 = self.force_configuration_pack()
        data = {
            "configuration": configuration_pack2.configuration.pk,
            "pack": configuration_pack2.pack.pk
        }
        response = self.put_json_data(reverse("osquery_api:configuration_pack", args=(configuration_pack.pk,)), data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "non_field_errors": ["The fields configuration, pack must make a unique set."]
        })

    def test_update_configuration_pack(self):
        self.set_permissions("osquery.change_configurationpack")
        configuration_pack = self.force_configuration_pack(force_tags=True)
        new_configuration = self.force_configuration()
        new_pack = self.force_pack()
        new_tag = self.force_tags(1)
        data = {
            "configuration": new_configuration.pk,
            "pack": new_pack.pk,
            "tags": [t.id for t in new_tag]
        }
        response = self.put_json_data(reverse("osquery_api:configuration_pack", args=(configuration_pack.pk,)), data)
        self.assertEqual(response.status_code, 200)
        configuration_pack.refresh_from_db()
        self.assertEqual(response.json(), {
            "id": configuration_pack.pk,
            "configuration": new_configuration.pk,
            "tags": [t.id for t in new_tag],
            "pack": new_pack.pk
        })
        self.assertEqual(configuration_pack.configuration, new_configuration)
        self.assertEqual(configuration_pack.tags.count(), 1)
        self.assertEqual(configuration_pack.pack, new_pack)

    # create configuration pack

    def test_create_configuration_pack_unauthorized(self):
        response = self.post_json_data(reverse("osquery_api:configuration_packs"), {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_create_configuration_pack_permission_denied(self):
        response = self.post_json_data(reverse("osquery_api:configuration_packs"), {})
        self.assertEqual(response.status_code, 403)

    def test_create_configuration_pack_fields_empty(self):
        self.set_permissions("osquery.add_configurationpack")
        response = self.post_json_data(reverse("osquery_api:configuration_packs"), {})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "configuration": ["This field is required."],
            "pack": ["This field is required."]
        })

    def test_create_configuration_pack_conflict(self):
        self.set_permissions("osquery.add_configurationpack")
        configuration_pack = self.force_configuration_pack(force_tags=True)
        data = {
            "configuration": configuration_pack.configuration.pk,
            "pack": configuration_pack.pack.pk,
        }
        response = self.post_json_data(reverse("osquery_api:configuration_packs"), data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "non_field_errors": ["The fields configuration, pack must make a unique set."]
        })

    def test_create_configuration_pack_configuration_with_multiple_packs(self):
        self.set_permissions("osquery.add_configurationpack")
        configuration = self.force_configuration()
        packs = [self.force_pack().pk for i in range(0, 3)]
        for pack in packs:
            data = {
                "configuration": configuration.pk,
                "pack": pack
            }
            response = self.post_json_data(reverse("osquery_api:configuration_packs"), data)
            self.assertEqual(response.status_code, 201)
            configuration_pack = ConfigurationPack.objects.filter(
                configuration_id=configuration.pk,
                pack_id=pack
            ).first()
            self.assertEqual(response.json(), {
                "id": configuration_pack.pk,
                "configuration": configuration.pk,
                "tags": [],
                "pack": pack
            })
            self.assertEqual(configuration_pack.pack.pk, pack)
            self.assertEqual(configuration_pack.configuration.pk, configuration.pk)
        result = ConfigurationPack.objects.filter(configuration_id=configuration.pk).count()
        self.assertEqual(result, 3)

    def test_create_configuration_pack_with_pack_id_from_existing(self):
        self.set_permissions("osquery.add_configurationpack")
        existing_configuration_pack = self.force_configuration_pack()
        configuration = self.force_configuration()
        data = {
            "configuration": configuration.pk,
            "pack": existing_configuration_pack.pack.pk,
        }
        response = self.post_json_data(reverse("osquery_api:configuration_packs"), data)
        self.assertEqual(response.status_code, 201)
        configuration_pack = ConfigurationPack.objects.get(pk=response.json()["id"])
        self.assertEqual(response.json(), {
            "id": configuration_pack.pk,
            "configuration": configuration.pk,
            "tags": [],
            "pack": configuration_pack.pack.pk
        })
        self.assertEqual(configuration_pack.configuration, configuration)

    def test_create_configuration_pack(self):
        self.set_permissions("osquery.add_configurationpack")
        configuration = self.force_configuration()
        pack = self.force_pack()
        tags = self.force_tags(1)
        data = {
            "configuration": configuration.pk,
            "pack": pack.pk,
            "tags": [t.id for t in tags]
        }
        response = self.post_json_data(reverse("osquery_api:configuration_packs"), data)
        self.assertEqual(response.status_code, 201)
        configuration_pack = ConfigurationPack.objects.first()
        self.assertEqual(response.json(), {
            "id": configuration_pack.pk,
            "configuration": configuration.pk,
            "tags": [t.id for t in tags],
            "pack": pack.pk
        })
        self.assertEqual(configuration_pack.configuration, configuration)
        self.assertEqual(configuration_pack.pack, pack)
        self.assertEqual(configuration_pack.tags.count(), 1)

    # delete configuration pack

    def test_delete_configuration_pack_unauthorized(self):
        response = self.delete(reverse("osquery_api:configuration_pack", args=(1,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_configuration_pack_permission_denied(self):
        response = self.delete(reverse("osquery_api:configuration_pack", args=(1,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_configuration_pack_not_found(self):
        self.set_permissions("osquery.delete_configurationpack")
        response = self.delete(reverse("osquery_api:configuration_pack", args=(9999,)))
        self.assertEqual(response.status_code, 404)

    def test_delete_configuration_pack(self):
        self.set_permissions("osquery.delete_configurationpack")
        configuration_pack = self.force_configuration_pack()
        response = self.delete(reverse("osquery_api:configuration_pack", args=(configuration_pack.pk,)))
        self.assertEqual(response.status_code, 204)
        self.assertEqual(ConfigurationPack.objects.count(), 0)

    # list pack queries

    def test_get_pack_queryies_unauthorized(self):
        response = self.get(reverse("osquery_api:pack_queries"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_pack_queryies_permission_denied(self):
        response = self.get(reverse("osquery_api:pack_queries"))
        self.assertEqual(response.status_code, 403)

    def test_get_pack_queryies_filter_by_pack_id_not_found(self):
        self.set_permissions("osquery.view_packquery")
        response = self.get(reverse("osquery_api:pack_queries"), {"pack_id": 9999})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            'pack_id': ['Select a valid choice. That choice is not one of the available choices.']
        })

    def test_get_pack_queryies_filter_by_pack_id(self):
        self.set_permissions("osquery.view_packquery")
        for _ in range(3):
            self.force_pack_query()
        pack_query = self.force_pack_query()
        response = self.get(reverse("osquery_api:pack_queries"), {"pack_id": pack_query.pack.pk})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            'id': pack_query.pk,
            'slug': pack_query.slug,
            'pack': pack_query.pack.pk,
            'query': pack_query.query.pk,
            'interval': 60,
            'log_removed_actions': False,
            'snapshot_mode': False,
            'shard': None,
            'can_be_denylisted': True,
            'created_at': pack_query.created_at.isoformat(),
            'updated_at': pack_query.updated_at.isoformat()
        }])

    def test_get_pack_queryies(self):
        self.set_permissions("osquery.view_packquery")
        pack_query = self.force_pack_query()
        response = self.get(reverse("osquery_api:pack_queries"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            'id': pack_query.pk,
            'slug': pack_query.slug,
            'pack': pack_query.pack.pk,
            'query': pack_query.query.pk,
            'interval': 60,
            'log_removed_actions': False,
            'snapshot_mode': False,
            'shard': None,
            'can_be_denylisted': True,
            'created_at': pack_query.created_at.isoformat(),
            'updated_at': pack_query.updated_at.isoformat(),
        }])

    # get pack query

    def test_get_pack_query_unauthorized(self):
        response = self.get(reverse("osquery_api:pack_query", args=(1,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_pack_query_permission_denied(self):
        response = self.get(reverse("osquery_api:pack_query", args=(1,)))
        self.assertEqual(response.status_code, 403)

    def test_get_pack_query_not_found(self):
        self.set_permissions("osquery.view_packquery")
        response = self.get(reverse("osquery_api:pack_query", args=(9999,)))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {
            "detail": "Not found."
        })

    def test_get_pack_query(self):
        self.set_permissions("osquery.view_packquery")
        pack_query = self.force_pack_query()
        response = self.get(reverse("osquery_api:pack_query", args=(pack_query.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            "id": pack_query.pk,
            "slug": pack_query.slug,
            "pack": pack_query.pack.pk,
            "query": pack_query.query.pk,
            "interval": 60,
            "log_removed_actions": False,
            "snapshot_mode": False,
            "shard": None,
            "can_be_denylisted": True,
            "created_at": pack_query.created_at.isoformat(),
            "updated_at": pack_query.updated_at.isoformat()
        })

    # update pack query

    def test_update_pack_query_unauthorized(self):
        response = self.put_json_data(reverse("osquery_api:pack_query", args=(1,)), {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_update_pack_query_permission_denied(self):
        response = self.put_json_data(reverse("osquery_api:pack_query", args=(1,)), {})
        self.assertEqual(response.status_code, 403)

    def test_update_pack_query_not_found(self):
        self.set_permissions("osquery.change_packquery")
        response = self.put_json_data(reverse("osquery_api:pack_query", args=(9999,)), {})
        self.assertEqual(response.status_code, 404)

    def test_update_pack_query_query_conflict(self):
        self.set_permissions("osquery.change_packquery")
        pack_query = self.force_pack_query()
        pack_query2 = self.force_pack_query()
        new_pack = self.force_pack()
        data = {
            "pack": new_pack.pk,
            "query": pack_query2.query.pk,
            "interval": 120
        }
        response = self.put_json_data(reverse("osquery_api:pack_query", args=(pack_query.pk,)), data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "query": ["This field must be unique."]
        })

    def test_update_pack_query_slug_exists(self):
        self.set_permissions("osquery.change_packquery")
        pack_query = self.force_pack_query()
        pack_query2 = self.force_pack_query()
        query_name = pack_query.query.name.upper()
        new_query = self.force_query(query_name=query_name)
        data = {
            "pack": pack_query.pack.pk,
            "query": new_query.pk,
            "interval": 120
        }
        response = self.put_json_data(reverse("osquery_api:pack_query", args=(pack_query2.pk,)), data)
        pack_query2.refresh_from_db()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            "id": pack_query2.pk,
            "slug": slugify(f"{query_name}-{new_query.pk}"),
            "pack": pack_query.pack.pk,
            "query": new_query.pk,
            "interval": 120,
            "log_removed_actions": False,
            "snapshot_mode": False,
            "shard": None,
            "can_be_denylisted": True,
            "created_at": pack_query2.created_at.isoformat(),
            "updated_at": pack_query2.updated_at.isoformat()
        })
        self.assertEqual(pack_query2.slug, slugify(f"{query_name}-{new_query.pk}"))
        self.assertEqual(pack_query2.query, new_query)
        self.assertEqual(pack_query2.interval, 120)

    def test_update_pack_query_log_removed_actions_snapshot_mode_conflict(self):
        self.set_permissions("osquery.change_packquery")
        pack_query = self.force_pack_query()
        data = {
            "pack": pack_query.pack.pk,
            "query": pack_query.query.pk,
            "interval": 120,
            "log_removed_actions": True,
            "snapshot_mode": True
        }
        response = self.put_json_data(reverse("osquery_api:pack_query", args=(pack_query.pk,)), data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "log_removed_actions": ["'log_removed_actions' and 'snapshot_mode' are mutually exclusive"],
            "snapshot_mode": ["'log_removed_actions' and 'snapshot_mode' are mutually exclusive"]
        })

    def test_update_pack_query_snapshot_mode_compliance_check_conflict(self):
        self.set_permissions("osquery.change_packquery")
        pack_query = self.force_pack_query(force_snapshot_mode=True, compliance_check=True)
        data = {
            "pack": pack_query.pack.pk,
            "query": pack_query.query.pk,
            "interval": 120,
            "snapshot_mode": False
        }
        response = self.put_json_data(reverse("osquery_api:pack_query", args=(pack_query.pk,)), data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "snapshot_mode": ["A compliance check query can only be scheduled in 'snapshot' mode."]
        })

    def test_update_pack_query_fields_invalid(self):
        self.set_permissions("osquery.change_packquery")
        pack_query = self.force_pack_query()
        data = {
            "pack": 9999,
            "query": 9999,
            "interval": 9,
            "shard": 101
        }
        response = self.put_json_data(reverse("osquery_api:pack_query", args=(pack_query.pk,)), data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "pack": ['Invalid pk "9999" - object does not exist.'],
            "query": ['Invalid pk "9999" - object does not exist.'],
            "interval": ["Ensure this value is greater than or equal to 10."],
            "shard": ["Ensure this value is less than or equal to 100."]
        })

    def test_update_pack_query(self):
        self.set_permissions("osquery.change_packquery")
        pack_query = self.force_pack_query()
        new_pack = self.force_pack()
        new_query = self.force_query(compliance_check=True)
        data = {
            "pack": new_pack.pk,
            "query": new_query.pk,
            "interval": 60,
            "log_removed_actions": False,
            "snapshot_mode": True,
            "can_be_denylisted": True,
            "shard": 10
        }
        response = self.put_json_data(reverse("osquery_api:pack_query", args=(pack_query.pk,)), data)
        self.assertEqual(response.status_code, 200)
        pack_query.refresh_from_db()
        self.assertEqual(response.json(), {
            "id": pack_query.pk,
            "slug": slugify(new_query.name),
            "pack": new_pack.pk,
            "query": new_query.pk,
            "interval": 60,
            "log_removed_actions": False,
            "snapshot_mode": True,
            "shard": 10,
            "can_be_denylisted": True,
            "created_at": pack_query.created_at.isoformat(),
            "updated_at": pack_query.updated_at.isoformat()
        })
        self.assertEqual(pack_query.slug, slugify(new_query.name))
        self.assertEqual(pack_query.pack, new_pack)
        self.assertEqual(pack_query.query, new_query)
        self.assertEqual(pack_query.interval, 60)
        self.assertEqual(pack_query.log_removed_actions, False)
        self.assertEqual(pack_query.snapshot_mode, True)
        self.assertEqual(pack_query.shard, 10)
        self.assertEqual(pack_query.can_be_denylisted, True)

    # create pack query

    def test_create_pack_query_unauthorized(self):
        response = self.post_json_data(reverse("osquery_api:pack_queries"), {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_create_pack_query_permission_denied(self):
        response = self.post_json_data(reverse("osquery_api:pack_queries"), {})
        self.assertEqual(response.status_code, 403)

    def test_create_pack_query_query_conflict(self):
        self.set_permissions("osquery.add_packquery")
        pack = self.force_pack()
        pack_query = self.force_pack_query()
        data = {
            "pack": pack.pk,
            "query": pack_query.query.pk,
            "interval": 60,
            "log_removed_actions": False,
            "snapshot_mode": False,
            "shard": None,
            "can_be_denylisted": True,
        }
        response = self.post_json_data(reverse("osquery_api:pack_queries"), data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "query": ['This field must be unique.']
        })

    def test_create_pack_query_slug_exists(self):
        query_name = "testquery"
        self.set_permissions("osquery.add_packquery")
        self.force_pack_query(query_name=query_name)
        query = self.force_query(query_name=query_name.upper())
        pack = self.force_pack()
        data = {
            "pack": pack.pk,
            "query": query.pk,
            "interval": 60,
            "log_removed_actions": False,
            "snapshot_mode": False,
            "shard": None,
            "can_be_denylisted": True,
        }
        response = self.post_json_data(reverse("osquery_api:pack_queries"), data)
        pack_query = PackQuery.objects.get(query=query)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json(), {
            "id": pack_query.pk,
            "slug": f"{query_name}-{query.pk}",
            "pack": pack.pk,
            "query": query.pk,
            "interval": 60,
            "log_removed_actions": False,
            "snapshot_mode": False,
            "shard": None,
            "can_be_denylisted": True,
            "created_at": pack_query.created_at.isoformat(),
            "updated_at": pack_query.updated_at.isoformat()
        })
        self.assertEqual(pack_query.slug, f"{query_name}-{query.pk}")
        self.assertEqual(pack_query.pack, pack)
        self.assertEqual(pack_query.query, query)
        self.assertEqual(pack_query.interval, 60)
        self.assertEqual(pack_query.log_removed_actions, False)
        self.assertEqual(pack_query.snapshot_mode, False)
        self.assertEqual(pack_query.shard, None)
        self.assertEqual(pack_query.can_be_denylisted, True)

    def test_create_pack_query_log_removed_actions_snapshot_mode_conflict(self):
        self.set_permissions("osquery.add_packquery")
        pack = self.force_pack()
        query = self.force_query()
        data = {
            "pack": pack.pk,
            "query": query.pk,
            "interval": 60,
            "log_removed_actions": True,
            "snapshot_mode": True
        }
        response = self.post_json_data(reverse("osquery_api:pack_queries"), data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "log_removed_actions": ["'log_removed_actions' and 'snapshot_mode' are mutually exclusive"],
            "snapshot_mode": ["'log_removed_actions' and 'snapshot_mode' are mutually exclusive"]
        })

    def test_create_pack_query_snapshot_mode_compliance_check_conflict(self):
        self.set_permissions("osquery.add_packquery")
        pack = self.force_pack()
        query = self.force_query(compliance_check=True)
        data = {
            "pack": pack.pk,
            "query": query.pk,
            "interval": 60,
            "snapshot_mode": False
        }
        response = self.post_json_data(reverse("osquery_api:pack_queries"), data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "snapshot_mode": ["A compliance check query can only be scheduled in 'snapshot' mode."]
        })

    def test_create_pack_query_fields_invalid(self):
        self.set_permissions("osquery.add_packquery")
        data = {
            "pack": 9999,
            "query": 9999,
            "interval": 9,
            "shard": 101
        }
        response = self.post_json_data(reverse("osquery_api:pack_queries"), data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "pack": ['Invalid pk "9999" - object does not exist.'],
            "query": ['Invalid pk "9999" - object does not exist.'],
            "interval": ["Ensure this value is greater than or equal to 10."],
            "shard": ["Ensure this value is less than or equal to 100."]
        })

    def test_create_pack_query(self):
        self.set_permissions("osquery.add_packquery")
        pack = self.force_pack()
        query = self.force_query()
        data = {
            "pack": pack.pk,
            "query": query.pk,
            "interval": 60,
            "log_removed_actions": False,
            "snapshot_mode": False,
            "shard": 50,
            "can_be_denylisted": True,
        }
        response = self.post_json_data(reverse("osquery_api:pack_queries"), data)
        self.assertEqual(response.status_code, 201)
        pack_query = PackQuery.objects.first()
        self.assertEqual(response.json(), {
            "id": pack_query.pk,
            "slug": slugify(query.name),
            "pack": pack.pk,
            "query": query.pk,
            "interval": 60,
            "log_removed_actions": False,
            "snapshot_mode": False,
            "shard": 50,
            "can_be_denylisted": True,
            "created_at": pack_query.created_at.isoformat(),
            "updated_at": pack_query.updated_at.isoformat()
        })
        self.assertEqual(pack_query.slug, slugify(query.name))
        self.assertEqual(pack_query.pack, pack)
        self.assertEqual(pack_query.query, query)
        self.assertEqual(pack_query.interval, 60)
        self.assertEqual(pack_query.log_removed_actions, False)
        self.assertEqual(pack_query.snapshot_mode, False)
        self.assertEqual(pack_query.shard, 50)
        self.assertEqual(pack_query.can_be_denylisted, True)

    # delete pack query

    def test_delete_pack_query_unauthorized(self):
        response = self.delete(reverse("osquery_api:pack_query", args=[1]), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_pack_query_permission_denied(self):
        response = self.delete(reverse("osquery_api:pack_query", args=[1]))
        self.assertEqual(response.status_code, 403)

    def test_delete_pack_query_not_found(self):
        self.set_permissions("osquery.delete_packquery")
        response = self.delete(reverse("osquery_api:pack_query", args=[9999]))
        self.assertEqual(response.status_code, 404)

    def test_delete_pack_query(self):
        self.set_permissions("osquery.delete_packquery")
        pack_query = self.force_pack_query()
        response = self.delete(reverse("osquery_api:pack_query", args=[pack_query.pk]))
        self.assertEqual(response.status_code, 204)
        self.assertEqual(PackQuery.objects.count(), 0)

    # terraform export

    def test_terraform_export_redirect(self):
        self.login_redirect(reverse("osquery:terraform_export"))

    def test_terraform_export_permission_denied(self):
        self.login("osquery.view_configuration")
        response = self.client.get(reverse("osquery:terraform_export"))
        self.assertEqual(response.status_code, 403)

    def test_terraform_export(self):
        self.login(
            "osquery.view_automatictableconstruction",
            "osquery.view_configuration",
            "osquery.view_configurationpack",
            "osquery.view_enrollment",
            "osquery.view_filecategory",
            "osquery.view_pack",
            "osquery.view_packquery",
            "osquery.view_query",
        )
        self.force_configuration(force_atc=True, force_file_category=True, force_pack=True)
        self.force_enrollment()
        self.force_pack_query()
        response = self.client.get(reverse("osquery:terraform_export"))
        self.assertEqual(response.status_code, 200)
