from django.test import TestCase
from .utils import force_realm_group, force_realm_tag_mapping, force_realm_user


class RealmModelsTestCase(TestCase):
    def test_no_tag_mapping_no_mapped_tags(self):
        group = force_realm_group()
        _, user = force_realm_user(realm=group.realm, group=group)
        tta, ttr = user.mapped_tags()
        self.assertEqual(len(tta), 0)
        self.assertEqual(len(ttr), 0)

    def test_group_mappings_one_tag_to_add_one_tag_to_remove(self):
        group = force_realm_group(display_name="YoLo")
        sub_group = force_realm_group(parent=group)
        _, user = force_realm_user(realm=group.realm, group=sub_group)
        _, tm1 = force_realm_tag_mapping(realm=group.realm, group_name="yolo")
        _, tm2 = force_realm_tag_mapping(realm=group.realm, group_name="fomo")
        tta, ttr = user.mapped_tags()
        self.assertEqual(tta, [tm1.tag])
        self.assertEqual(ttr, [tm2.tag])
