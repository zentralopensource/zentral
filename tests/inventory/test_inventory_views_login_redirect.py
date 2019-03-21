import urllib.parse
from django.urls import reverse
from django.test import TestCase, override_settings
from zentral.contrib.inventory.models import BusinessUnit, MachineSnapshotCommit, MachineTag, Tag
from accounts.models import User


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class InventoryLoginRedirectTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # user
        cls.pwd = "godzillapwd"
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", cls.pwd)
        source = {"module": "tests.zentral.io", "name": "Zentral Tests"}
        tree = {
            "source": source,
            "business_unit": {"name": "yo bu",
                              "reference": "bu1",
                              "source": source,
                              "links": [{"anchor_text": "bu link",
                                         "url": "http://bu-link.de"}]},
            "groups": [{"name": "yo grp",
                        "reference": "grp1",
                        "source": source,
                        "links": [{"anchor_text": "group link",
                                   "url": "http://group-link.de"}]}],
            "serial_number": "0123456789",
            "os_version": {'name': 'OS X', 'major': 10, 'minor': 11, 'patch': 1},
            "osx_app_instances": [
                {'app': {'bundle_id': 'io.zentral.baller',
                         'bundle_name': 'Baller.app',
                         'bundle_version': '123',
                         'bundle_version_str': '1.2.3'},
                 'bundle_path': "/Applications/Baller.app"}
            ]
        }
        _, cls.ms = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        cls.group_id = cls.ms.groups.all()[0].pk
        cls.bu_id = cls.ms.business_unit.pk
        cls.mbu_id = cls.ms.business_unit.meta_business_unit.pk
        cls.osx_app_instance = cls.ms.osx_app_instances.all()[0]
        tree = {"name": "yo bu2",
                "reference": "bu2",
                "source": source}
        cls.bu2, _ = BusinessUnit.objects.commit(tree)
        cls.bu2_id = cls.bu2.pk
        cls.mbu2_id = cls.bu2.meta_business_unit.pk
        cls.tag1 = Tag.objects.create(name="tag1")
        MachineTag.objects.create(tag=cls.tag1, serial_number=cls.ms.serial_number)
        cls.tag2 = Tag.objects.create(name="tag2", meta_business_unit=cls.bu2.meta_business_unit)

    def login_redirect(self, url_name, *args, query=None):
        url = reverse("inventory:{}".format(url_name), args=args)
        if query:
            url = "{u}?{q}".format(u=url, q=query)
        response = self.client.get(url)
        self.assertRedirects(response, "{u}?{q}".format(u=reverse("login"),
                                                        q=urllib.parse.urlencode({"next": url}, safe="/")))

    def test_index(self):
        self.login_redirect("index", query="sf=mbu-t-tp-hm-pf-osv")

    def test_groups(self):
        self.login_redirect("groups")

    def test_group_machines(self):
        self.login_redirect("group_machines", self.group_id, query="sf=mbu-t-tp-hm-pf-osv")

    def test_business_units(self):
        self.login_redirect("mbu")

    def test_business_units_merge_review(self):
        self.login_redirect("review_mbu_merge")

    def test_business_units_merge(self):
        self.login_redirect("merge_mbu")

    def test_business_units_create(self):
        self.login_redirect("create_mbu")

    def test_business_units_update(self):
        self.login_redirect("update_mbu", self.mbu_id)

    def test_business_units_tags(self):
        self.login_redirect("mbu_tags", self.mbu2_id)

    def test_business_units_remove_tag(self):
        self.login_redirect("remove_mbu_tag", self.mbu2_id, self.tag2.id)

    def test_business_units_machines(self):
        self.login_redirect("mbu_machines", self.mbu_id, query="sf=mbu-t-tp-hm-pf-osv")

    def test_business_units_detach_bu(self):
        self.login_redirect("detach_bu", self.mbu_id, self.bu_id)

    def test_business_units_api_enrollment(self):
        self.login_redirect("mbu_api_enrollment", self.mbu_id)

    def test_machine_events(self):
        self.login_redirect("machine_events", self.ms.serial_number)

    def test_machine_tags(self):
        self.login_redirect("machine_tags", self.ms.serial_number)

    def test_remove_machine_tag(self):
        self.login_redirect("remove_machine_tag", self.ms.serial_number, self.tag1.id)

    def test_archive_machine(self):
        self.login_redirect("archive_machine", self.ms.serial_number)

    def test_machine(self):
        self.login_redirect("machine", self.ms.serial_number)

    def test_tags(self):
        self.login_redirect("tags")

    def test_tag_update(self):
        self.login_redirect("update_tag", self.tag1.id)

    def test_tag_delete(self):
        self.login_redirect("delete_tag", self.tag1.id)

    def test_macos_apps(self):
        self.login_redirect("macos_apps")

    def test_macos_app(self):
        self.login_redirect("macos_app", self.osx_app_instance.app.id)

    def test_macos_app_instance_machines(self):
        self.login_redirect("macos_app_instance_machines",
                            self.osx_app_instance.app.id,
                            self.osx_app_instance.id,
                            query="sf=mbu-t-tp-hm-pf-osv")
