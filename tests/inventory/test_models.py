from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import BusinessUnit, MetaBusinessUnit, Tag, Taxonomy


class InventoryModelsTestCase(TestCase):
    def test_business_unit_key(self):
        business_unit, _ = BusinessUnit.objects.commit({
            "name": "un",
            "reference": "#1",
            "source": {
                "module": "io.zentral.tests",
                "name": "test"
            }
        })
        self.assertEqual(business_unit.key, "bcb623ccac3ccabd4761d2aaaf568ba00b4d6edb")

    def test_business_unit_key_equality(self):
        # key only based on reference and source
        reference = get_random_string(12)
        business_unit1, _ = BusinessUnit.objects.commit({
            "name": get_random_string(12),
            "reference": reference,
            "source": {
                "module": "io.zentral.tests",
                "name": "test"
            }
        })
        business_unit2, _ = BusinessUnit.objects.commit({
            "name": get_random_string(11),
            "reference": reference,
            "source": {
                "module": "io.zentral.tests",
                "name": "test"
            }
        })
        self.assertNotEqual(business_unit1, business_unit2)
        self.assertEqual(business_unit1.key, business_unit2.key)

    def test_business_unit_meta_business_unit_different_key_different_name(self):
        # business units with different key and name will be attached to different meta business units
        business_unit1, _ = BusinessUnit.objects.commit({
            "name": get_random_string(12),
            "reference": get_random_string(12),
            "source": {
                "module": "io.zentral.tests",
                "name": "test"
            }
        })
        business_unit2, _ = BusinessUnit.objects.commit({
            "name": get_random_string(12),
            "reference": get_random_string(12),
            "source": {
                "module": "io.zentral.tests2",
                "name": "test2"
            }
        })
        self.assertNotEqual(business_unit1.meta_business_unit, business_unit2.meta_business_unit)
        self.assertEqual(business_unit1.meta_business_unit.name, business_unit1.name)
        self.assertEqual(business_unit2.meta_business_unit.name, business_unit2.name)

    def test_business_unit_meta_business_unit_same_key(self):
        # business units with same key will be attached to same meta business unit
        reference = get_random_string(12)
        business_unit1, _ = BusinessUnit.objects.commit({
            "name": get_random_string(12),
            "reference": reference,
            "source": {
                "module": "io.zentral.tests",
                "name": "test"
            }
        })
        business_unit2, _ = BusinessUnit.objects.commit({
            "name": get_random_string(11),
            "reference": reference,
            "source": {
                "module": "io.zentral.tests",
                "name": "test"
            }
        })
        self.assertEqual(business_unit1.meta_business_unit, business_unit2.meta_business_unit)
        self.assertEqual(business_unit1.meta_business_unit.name, business_unit1.name)

    def test_business_unit_meta_business_unit_same_name(self):
        # business unit with unknown key will be attached to know meta business unit with same name
        name = get_random_string(12)
        business_unit1, _ = BusinessUnit.objects.commit({
            "name": name,
            "reference": get_random_string(),
            "source": {
                "module": "io.zentral.tests",
                "name": "test"
            }
        })
        business_unit2, _ = BusinessUnit.objects.commit({
            "name": name,
            "reference": get_random_string(),
            "source": {
                "module": "io.zentral.tests2",
                "name": "test2"
            }
        })
        self.assertEqual(business_unit1.meta_business_unit, business_unit2.meta_business_unit)
        self.assertEqual(business_unit1.meta_business_unit.name, business_unit1.name)

    def test_meta_business_unit_serialize_for_event_keys_only(self):
        mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        mbu.create_enrollment_business_unit()
        self.assertEqual(
            mbu.serialize_for_event(keys_only=True),
            {"pk": mbu.pk, "name": mbu.name}
        )

    def test_meta_business_unit_serialize_for_event(self):
        mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        mbu.create_enrollment_business_unit()
        self.assertEqual(
            mbu.serialize_for_event(),
            {"pk": mbu.pk, "name": mbu.name,
             "api_enrollment_enabled": True,
             "created_at": mbu.created_at,
             "updated_at": mbu.updated_at}
        )

    def test_taxonomy_serialize_for_event_keys_only(self):
        mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        name = get_random_string(12)
        taxonomy = Taxonomy.objects.create(name=name, meta_business_unit=mbu)
        self.assertEqual(
            taxonomy.serialize_for_event(keys_only=True),
            {"pk": taxonomy.pk, "name": taxonomy.name}
        )

    def test_taxonomy_serialize_for_event(self):
        mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        name = get_random_string(12)
        taxonomy = Taxonomy.objects.create(name=name, meta_business_unit=mbu)
        self.assertEqual(
            taxonomy.serialize_for_event(),
            {"pk": taxonomy.pk, "name": taxonomy.name,
             "meta_business_unit": {"pk": mbu.pk, "name": mbu.name},
             "created_at": taxonomy.created_at,
             "updated_at": taxonomy.updated_at}
        )

    def test_tag_serialize_for_event_keys_only(self):
        name = get_random_string(12)
        tag = Tag.objects.create(name=name)
        self.assertEqual(
            tag.serialize_for_event(keys_only=True),
            {"pk": tag.pk, "name": name}
        )

    def test_tag_serialize_for_event(self):
        name = get_random_string(12)
        taxonomy_name = get_random_string(12)
        taxonomy = Taxonomy.objects.create(name=taxonomy_name)
        tag = Tag.objects.create(taxonomy=taxonomy, name=name)
        self.assertEqual(
            tag.serialize_for_event(),
            {"pk": tag.pk, "name": name,
             "taxonomy": {"pk": taxonomy.pk, "name": taxonomy.name},
             "color": "0079bf",
             "slug": name.lower()}
        )
