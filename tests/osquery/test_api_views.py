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
from django.test import TestCase
from accounts.models import APIToken, User
from zentral.conf import settings
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit, Tag
from zentral.contrib.inventory.serializers import EnrollmentSecretSerializer
from zentral.contrib.osquery.compliance_checks import sync_query_compliance_check
from zentral.contrib.osquery.models import Configuration, DistributedQuery, Enrollment, Pack, PackQuery, Query, \
    AutomaticTableConstruction, FileCategory
from zentral.core.compliance_checks.models import ComplianceCheck


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

    def force_configuration(self, force_atc=False):
        if force_atc:
            atc = self.force_atc()
            conf = Configuration.objects.create(name=get_random_string(12))
            conf.automatic_table_constructions.set([atc])
            return conf, atc
        return Configuration.objects.create(name=get_random_string(12))

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
        return Pack.objects.create(name=name, slug=slugify(name))

    def force_query(self, pack_query_mode=None, compliance_check=False):
        if compliance_check:
            sql = "select 'OK' as ztl_status;"
        else:
            sql = "SELECT * FROM osquery_schedule;"
        query = Query.objects.create(name=get_random_string(12), sql=sql)
        if pack_query_mode is not None:
            pack = self.force_pack()
            if pack_query_mode == "diff":
                PackQuery.objects.create(
                    pack=pack, query=query, interval=60, slug=slugify(query.name), log_removed_actions=False,
                    snapshot_mode=False)
            elif pack_query_mode == "snapshot":
                PackQuery.objects.create(
                    pack=pack, query=query, interval=60, slug=slugify(query.name), log_removed_actions=False,
                    snapshot_mode=True)
        sync_query_compliance_check(query, compliance_check)
        query.refresh_from_db()
        return query

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

    def test_get_atcs_by_name(self):
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

    def test_get_atcs_by_configuration(self):
        configuration, atc = self.force_configuration(force_atc=True)
        configuration2, atc2 = self.force_configuration(force_atc=True)
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

    def test_get_atcs_by_configuration_not_found(self):
        self.set_permissions("osquery.view_automatictableconstruction")
        response = self.get(reverse('osquery_api:atcs'), data={"configuration_id": 99999})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"configuration_id": ["Select a valid choice. That choice is not one of the "
                                                                "available choices."]})

    def test_get_atcs_by_name_not_found(self):
        self.set_permissions("osquery.view_automatictableconstruction")
        response = self.get(reverse('osquery_api:atcs'), data={"name": get_random_string(24)})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])

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

    def test_update_atc_already_exists(self):
        configuration, atc = self.force_configuration(force_atc=True)
        configuration2, atc2 = self.force_configuration(force_atc=True)
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

    def test_create_atc_already_exists(self):
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

    def test_get_file_categories_by_name(self):
        file_category = self.force_file_category()
        file_category2 = self.force_file_category()
        self.set_permissions("osquery.view_filecategory")
        response = self.get(reverse('osquery_api:file_categories'), data={"name": file_category2.name})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            "name": file_category2.name,
            "slug": file_category2.slug,
            "id": file_category2.id,
            "file_paths": ['/home/yo'],
            "exclude_paths": ['/home/yo/exclude1', '/home/yo/exclude2'],
            "access_monitoring": False,
            "description": "description of the file category",
            "file_paths_queries": ['select * from file_paths where path like "/home/yo/";'],
            "updated_at": file_category2.updated_at.isoformat(),
            "created_at": file_category2.created_at.isoformat(),
        }])

    def test_get_file_categories_by_name_unknown(self):
        self.set_permissions("osquery.view_filecategory")
        response = self.get(reverse('osquery_api:file_categories'), data={"name": get_random_string(35)})
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.json(), list)
        self.assertEqual(response.json(), [])

    # get file category

    def test_get_file_category_unauthorized(self):
        response = self.get(reverse("osquery_api:file_category", args=[1]), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_file_category_permission_denied(self):
        response = self.get(reverse("osquery_api:file_category", args=[1]))
        self.assertEqual(response.status_code, 403)

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

    def test_get_file_category_not_exist(self):
        self.set_permissions("osquery.view_filecategory")
        response = self.get(reverse("osquery_api:file_category", args=[9999]))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {
            "detail": "Not found."
        })

    # create file category

    def test_create_file_category_unauthorized(self):
        response = self.post(reverse("osquery_api:file_categories"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_create_file_category_permission_denied(self):
        response = self.post(reverse("osquery_api:file_categories"))
        self.assertEqual(response.status_code, 403)

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

    def test_create_file_category_name_exist(self):
        file_category = self.force_file_category()
        self.set_permissions("osquery.add_filecategory")
        data = {"name": file_category.name}
        response = self.post_json_data(reverse("osquery_api:file_categories"), data=data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "name": [f"file category with this name already exists."]
        })

    def test_create_file_category_no_name(self):
        self.set_permissions("osquery.add_filecategory")
        data = {"name": ""}
        response = self.post_json_data(reverse("osquery_api:file_categories"), data=data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "name": ["This field may not be blank."]
        })

    def test_create_file_category_slug_conflict(self):
        file_category = self.force_file_category()
        self.set_permissions("osquery.add_filecategory")
        data = {"name": file_category.name.upper()}
        response = self.post_json_data(reverse("osquery_api:file_categories"), data=data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "name": [f"file category with this slug {file_category.slug} already exists."]
        })

    # update file category

    def test_update_file_category_unauthorized(self):
        response = self.put_json_data(reverse("osquery_api:file_category", args=[1]), {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_update_file_category_permission_denied(self):
        response = self.put_json_data(reverse("osquery_api:file_category", args=[1]), {})
        self.assertEqual(response.status_code, 403)

    def test_update_file_category_without_name(self):
        file_category = self.force_file_category()
        self.set_permissions("osquery.change_filecategory")
        data = {
            "name": "",
        }
        response = self.put_json_data(reverse("osquery_api:file_category", args=[file_category.id]), data=data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "name": ["This field may not be blank."]
        })

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

    def test_update_file_category_name_exist(self):
        file_category = self.force_file_category()
        file_category2 = self.force_file_category()
        self.set_permissions("osquery.change_filecategory")
        data = {"name": file_category.name}
        response = self.put_json_data(reverse("osquery_api:file_category", args=[file_category2.id]), data=data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "name": [f"file category with this name already exists."]
        })

    def test_update_file_category_not_exist(self):
        self.set_permissions("osquery.change_filecategory")
        data = {"name": "file category name"}
        response = self.put_json_data(reverse("osquery_api:file_category", args=[9999]), data=data)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {
            "detail": "Not found."
        })

    # delete file category

    def test_delete_file_category_unauthorized(self):
        response = self.delete(reverse("osquery_api:file_category", args=[1]), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_file_category_permission_denied(self):
        response = self.delete(reverse("osquery_api:file_category", args=[1]))
        self.assertEqual(response.status_code, 403)

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

    def test_get_configurations(self):
        config = self.force_configuration()
        self.set_permissions("osquery.view_configuration")
        response = self.get(reverse('osquery_api:configurations'), data={"name": config.name})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data,
                         [{"id": config.pk,
                           "name": config.name,
                           'description': "",
                           "inventory": True,
                           "inventory_apps": False,
                           "inventory_interval": 86400,
                           "options": {},
                           "created_at": config.created_at.isoformat(),
                           "updated_at": config.updated_at.isoformat()
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
             "options": {},
             "created_at": configuration.created_at.isoformat(),
             "updated_at": configuration.updated_at.isoformat()}
        )

    # create configuration

    def test_create_configuration(self):
        self.set_permissions("osquery.add_configuration")
        response = self.post_json_data(reverse('osquery_api:configurations'), {'name': 'Configuration0'})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(Configuration.objects.filter(name='Configuration0').count(), 1)
        configuration = Configuration.objects.get(name="Configuration0")
        self.assertEqual(configuration.name, 'Configuration0')

    # update configuration

    def test_update_configuration(self):
        config = self.force_configuration()
        new_name = get_random_string(12)
        data = {'name': new_name}
        self.set_permissions("osquery.change_configuration")
        response = self.put_json_data(reverse('osquery_api:configuration', args=(config.pk,)), data)
        self.assertEqual(response.status_code, 200)
        config.refresh_from_db()
        self.assertEqual(config.name, new_name)

    def test_update_configuration_name_exists(self):
        config0 = self.force_configuration()
        config1 = self.force_configuration()
        data = {'name': config0.name}
        self.set_permissions("osquery.change_configuration")
        response = self.put_json_data(reverse('osquery_api:configuration', args=(config1.pk,)), data)
        self.assertEqual(response.status_code, 400)
        response_j = response.json()
        self.assertEqual(response_j["name"][0], "configuration with this name already exists.")

    # delete configuration

    def test_delete_configuration(self):
        config = self.force_configuration()
        self.set_permissions("osquery.delete_configuration")
        response = self.delete(reverse('osquery_api:configuration', args=(config.pk,)))
        self.assertEqual(response.status_code, 204)

    def test_delete_configuration_error(self):
        config = self.force_configuration()
        enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=self.mbu)
        Enrollment.objects.create(configuration=config, secret=enrollment_secret)
        self.set_permissions("osquery.delete_configuration")
        response = self.delete(reverse('osquery_api:configuration', args=(config.pk,)))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), ["This configuration cannot be deleted"])

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

    # put pack

    def test_put_pack_unauthorized(self):
        url = reverse("osquery_api:pack", args=(get_random_string(12),))
        response = self.put_json_data(url, {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_put_pack_permission_denied(self):
        url = reverse("osquery_api:pack", args=(get_random_string(12),))
        response = self.put_json_data(url, {}, include_token=True)
        self.assertEqual(response.status_code, 403)

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
        for i in range(3):
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

    def test_delete_query_unauthorized(self):
        query = self.force_query()
        response = self.delete(reverse("osquery_api:query", args=(query.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_query_permission_denied(self):
        query = self.force_query()
        response = self.delete(reverse("osquery_api:query", args=(query.pk,)))
        self.assertEqual(response.status_code, 403)
