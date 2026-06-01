from django.http import QueryDict
from django.test import TestCase
from django.utils.crypto import get_random_string

from zentral.contrib.inventory.models import MachineSnapshotCommit, MachineTag, Tag
from zentral.contrib.inventory.utils import MSQuery
from zentral.contrib.inventory.utils.msquery import TagFilter


class MSQueryTestCase(TestCase):
    def test_unexisting_compliance_check_status_filter(self):
        self.assertEqual("?sf=", MSQuery(QueryDict("sf=ccs.100000000").copy()).get_url())


class TagFilterMultiBlockTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        source = {"module": "tests.zentral.io", "name": "Zentral Tests"}
        cls.serials = []
        for i in range(3):
            sn = "sn-{}-{}".format(i, get_random_string(6))
            tree = {
                "source": source,
                "serial_number": sn,
                "system_info": {"computer_name": "host-{}".format(i)},
            }
            MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
            cls.serials.append(sn)
        cls.tag_a = Tag.objects.create(name="tag-a")
        cls.tag_b = Tag.objects.create(name="tag-b")
        cls.tag_c = Tag.objects.create(name="tag-c")
        # serial 0: a + b
        MachineTag.objects.create(serial_number=cls.serials[0], tag=cls.tag_a)
        MachineTag.objects.create(serial_number=cls.serials[0], tag=cls.tag_b)
        # serial 1: a only
        MachineTag.objects.create(serial_number=cls.serials[1], tag=cls.tag_a)
        # serial 2: no tags

    def _msquery(self, qd_str=""):
        return MSQuery(QueryDict(qd_str, mutable=True))

    def _tag_filters(self, msquery):
        return [f for f in msquery.filters if isinstance(f, TagFilter)]

    # default behavior

    def test_default_mode_adds_one_empty_tag_block(self):
        msquery = self._msquery()
        tag_filters = self._tag_filters(msquery)
        self.assertEqual(len(tag_filters), 1)
        self.assertIsNone(tag_filters[0].value)
        self.assertEqual(msquery.count(), 3)

    def test_default_sf_serialization_unchanged(self):
        # backward compat with existing redirect test
        msquery = self._msquery()
        self.assertEqual(msquery.serialize_filters(), "mbu-t-mis-tp-pf-hm-osv")

    # sf parsing

    def test_sf_t_token_no_value(self):
        msquery = self._msquery("sf=mbu-t-mis-tp-pf-hm-osv")
        tag_filters = self._tag_filters(msquery)
        self.assertEqual(len(tag_filters), 1)
        self.assertIsNone(tag_filters[0].value)

    def test_sf_t_dot_value_token(self):
        msquery = self._msquery(f"sf=mbu-t.{self.tag_a.pk}-mis-tp-pf-hm-osv")
        tag_filters = self._tag_filters(msquery)
        self.assertEqual(len(tag_filters), 1)
        self.assertEqual(tag_filters[0].value, str(self.tag_a.pk))
        self.assertEqual(msquery.count(), 2)  # serials 0 and 1 have tag-a

    def test_sf_t_dot_zero_means_no_tag(self):
        msquery = self._msquery("sf=mbu-t.0-mis-tp-pf-hm-osv")
        tag_filters = self._tag_filters(msquery)
        self.assertEqual(tag_filters[0].value, TagFilter.none_value)
        # only serial 2 has no tags
        self.assertEqual(msquery.count(), 1)

    def test_sf_t_dot_invalid_triggers_redirect(self):
        msquery = self._msquery("sf=mbu-t.notanint-mis-tp-pf-hm-osv")
        self.assertTrue(msquery._redirect)

    # lateral-join shape

    def test_constrained_block_pushes_tag_id_into_lateral(self):
        # A block with a selected tag should produce a lateral subquery that
        # already filters by inventory_tag.id, so each lateral emits at most
        # one row per machine instead of the whole tag set.
        msquery = self._msquery(f"sf=mbu-t.{self.tag_a.pk}-mis-tp-pf-hm-osv")
        tag_filter = self._tag_filters(msquery)[0]
        (lateral, lateral_args), _ = tag_filter.joins()
        self.assertIn(f"t{tag_filter.idx} on TRUE", lateral)
        self.assertIn("inventory_tag.id = %s", lateral)
        self.assertEqual(lateral_args, [str(self.tag_a.pk)])

    def test_unconstrained_block_keeps_open_lateral(self):
        # An empty block has no value to push down; the lateral must stay open
        # so its grouping set still surfaces every tag of the matching machines.
        msquery = self._msquery("sf=mbu-t-mis-tp-pf-hm-osv")
        tag_filter = self._tag_filters(msquery)[0]
        (lateral, lateral_args), _ = tag_filter.joins()
        self.assertNotIn("inventory_tag.id = %s", lateral)
        self.assertEqual(lateral_args, [])

    def test_no_tag_block_does_not_push_into_lateral(self):
        # The "no tag" branch checks for absence of any tag (t{idx}.id is null)
        # and cannot be expressed inside the lateral; it must stay in the outer
        # WHERE clause and leave the lateral open.
        msquery = self._msquery("sf=mbu-t.0-mis-tp-pf-hm-osv")
        tag_filter = self._tag_filters(msquery)[0]
        (lateral, lateral_args), _ = tag_filter.joins()
        self.assertNotIn("inventory_tag.id = %s", lateral)
        self.assertEqual(lateral_args, [])
        self.assertIn(f"t{tag_filter.idx}.id is null", list(tag_filter.wheres()))

    def test_constrained_block_args_carried_to_grouping_query(self):
        # The lateral arg must reach the final query through
        # _iter_unique_joins_with_args so the SQL is correctly parameterized.
        msquery = self._msquery(f"sf=mbu-t.{self.tag_a.pk}-t.{self.tag_b.pk}-mis-tp-pf-hm-osv")
        query, args = msquery._build_grouping_query_with_args()
        self.assertEqual(query.count("inventory_tag.id = %s"), 2)
        # both tag pks must appear in the placeholder args (order follows
        # filter order, but we don't pin it here).
        self.assertIn(str(self.tag_a.pk), args)
        self.assertIn(str(self.tag_b.pk), args)

    def test_constrained_block_drops_outer_equality_clause(self):
        # The outer WHERE for a constrained block must reduce to a NOT NULL
        # check — keeping the equality there would duplicate the parameter
        # and re-introduce the wide-lateral behavior in cost-based planners.
        msquery = self._msquery(f"sf=mbu-t.{self.tag_a.pk}-mis-tp-pf-hm-osv")
        tag_filter = self._tag_filters(msquery)[0]
        wheres = list(tag_filter.wheres())
        self.assertEqual(wheres, [f"t{tag_filter.idx}.id is not null"])
        self.assertEqual(list(tag_filter.where_args()), [])

    # multi-block AND semantics

    def test_two_blocks_both_with_values_intersect(self):
        sf = f"sf=mbu-t.{self.tag_a.pk}-t.{self.tag_b.pk}-mis-tp-pf-hm-osv"
        msquery = self._msquery(sf)
        tag_filters = self._tag_filters(msquery)
        self.assertEqual(len(tag_filters), 2)
        # only serial 0 has BOTH tag-a and tag-b
        self.assertEqual(msquery.count(), 1)

    def test_two_blocks_no_intersection(self):
        # tag-b is on serial 0, tag-c on no machine
        sf = f"sf=mbu-t.{self.tag_b.pk}-t.{self.tag_c.pk}-mis-tp-pf-hm-osv"
        msquery = self._msquery(sf)
        self.assertEqual(msquery.count(), 0)

    def test_two_blocks_one_empty_acts_like_single_block(self):
        # block 1 picks tag-a, block 2 has no value → matches all machines with tag-a
        sf = f"sf=mbu-t.{self.tag_a.pk}-t-mis-tp-pf-hm-osv"
        msquery = self._msquery(sf)
        self.assertEqual(msquery.count(), 2)

    # stable removal

    def test_grouping_links_for_block_removal_preserve_other_block_value(self):
        sf = f"sf=mbu-t.{self.tag_a.pk}-t.{self.tag_b.pk}-mis-tp-pf-hm-osv"
        msquery = self._msquery(sf)
        tag_filters = self._tag_filters(msquery)
        # find the trash link (f_r_link) for the first tag block
        for f, _, f_r_link, _ in msquery.grouping_links():
            if f is tag_filters[0]:
                self.assertIsNotNone(f_r_link)
                # the kept block's value (tag_b) must still be in the resulting sf
                self.assertIn(f"t.{self.tag_b.pk}", f_r_link)
                # the removed block's value must be gone
                self.assertNotIn(f"t.{self.tag_a.pk}", f_r_link)
                return
        self.fail("first tag block not found in grouping_links")

    # available_filters

    def test_available_filters_includes_tags_when_present(self):
        msquery = self._msquery("sf=mbu-t-mis-tp-pf-hm-osv")
        titles = [title for title, _ in msquery.available_filters()]
        self.assertIn("Tags", titles)

    def test_add_filter_link_appends_t_token(self):
        msquery = self._msquery("sf=mbu-t-mis-tp-pf-hm-osv")
        for title, link in msquery.available_filters():
            if title == "Tags":
                self.assertEqual(link.count("sf=mbu-t-mis-tp-pf-hm-osv-t"), 1)
                return
        self.fail("Tags entry missing from available_filters")

    # canonical query dict

    def test_canonical_query_dict_keeps_value_in_sf_only(self):
        sf = f"sf=mbu-t.{self.tag_a.pk}-t.{self.tag_b.pk}-mis-tp-pf-hm-osv"
        msquery = self._msquery(sf)
        qd = msquery.get_canonical_query_dict()
        # value is in sf, not as separate query-dict entries
        self.assertIn(f"t.{self.tag_a.pk}", qd["sf"])
        self.assertIn(f"t.{self.tag_b.pk}", qd["sf"])
        self.assertNotIn("t0", qd)
        self.assertNotIn("t1", qd)

    # toggling

    def test_grouping_choice_down_link_sets_block_value_in_sf(self):
        # one block, no value picked yet
        msquery = self._msquery("sf=mbu-t-mis-tp-pf-hm-osv")
        tag_filters = self._tag_filters(msquery)
        for f, choices in msquery.grouping_choices():
            if f is not tag_filters[0]:
                continue
            for label, _, down_qd, _ in choices:
                if label == self.tag_a.name:
                    self.assertIsNotNone(down_qd)
                    self.assertIn(f"t.{self.tag_a.pk}", down_qd["sf"])
                    return
        self.fail("tag-a choice not found")

    def test_grouping_choice_up_link_clears_block_value(self):
        sf = f"sf=mbu-t.{self.tag_a.pk}-mis-tp-pf-hm-osv"
        msquery = self._msquery(sf)
        tag_filters = self._tag_filters(msquery)
        for f, choices in msquery.grouping_choices():
            if f is not tag_filters[0]:
                continue
            for label, _, _, up_qd in choices:
                if label == self.tag_a.name:
                    self.assertIsNotNone(up_qd)
                    # block value cleared, token reverts to bare "t"
                    self.assertNotIn(f"t.{self.tag_a.pk}", up_qd["sf"])
                    self.assertIn("-t-", "-" + up_qd["sf"] + "-")
                    return
        self.fail("active tag-a choice not found")

    # fetch shows tags

    def test_fetch_accumulates_tags_across_blocks(self):
        sf = f"sf=mbu-t.{self.tag_a.pk}-t.{self.tag_b.pk}-mis-tp-pf-hm-osv"
        msquery = self._msquery(sf)
        for serial_number, machine_snapshots in msquery.fetch():
            self.assertEqual(serial_number, self.serials[0])
            tag_names = {t["name"] for ms in machine_snapshots for t in ms.get("tags", [])}
            self.assertEqual(tag_names, {"tag-a", "tag-b"})
            return
        self.fail("expected one machine in result set")

    # block title

    def test_title_default_when_empty(self):
        msquery = self._msquery("sf=mbu-t-mis-tp-pf-hm-osv")
        self.assertEqual(self._tag_filters(msquery)[0].title, "Tags")

    def test_title_includes_picked_tag_name(self):
        msquery = self._msquery(f"sf=mbu-t.{self.tag_a.pk}-mis-tp-pf-hm-osv")
        self.assertEqual(self._tag_filters(msquery)[0].title, "Tags · tag-a")

    def test_title_no_tag_for_none_value(self):
        msquery = self._msquery("sf=mbu-t.0-mis-tp-pf-hm-osv")
        self.assertEqual(self._tag_filters(msquery)[0].title, "Tags · No tag")

    def test_title_falls_back_when_tag_missing(self):
        # sf-decoded lookup of a non-existent pk: title falls back to "Tags"
        msquery = self._msquery("sf=mbu-t.999999999-mis-tp-pf-hm-osv")
        self.assertEqual(self._tag_filters(msquery)[0].title, "Tags")

    # sibling exclusion

    def test_other_block_choices_skip_tag_picked_in_first_block(self):
        sf = f"sf=mbu-t.{self.tag_a.pk}-t-mis-tp-pf-hm-osv"
        msquery = self._msquery(sf)
        tag_filters = self._tag_filters(msquery)
        block0, block1 = tag_filters[0], tag_filters[1]
        # block 0 (which owns tag-a) still surfaces it as the active row
        block0_labels = {label for label, _, _, _ in block0.grouping_choices_from_grouping_results(
            msquery._get_grouping_results()
        )}
        self.assertIn(self.tag_a.name, block0_labels)
        # block 1's grouping includes tag-a in the raw results (machines having tag-a),
        # but the choice is suppressed because tag-a is already picked elsewhere
        block1_labels = {label for label, _, _, _ in block1.grouping_choices_from_grouping_results(
            msquery._get_grouping_results()
        )}
        self.assertNotIn(self.tag_a.name, block1_labels)

    def test_block_keeps_its_own_value_visible_when_other_block_unselected(self):
        # only one block has a value picked → that value still shows as active in its own block
        sf = f"sf=mbu-t.{self.tag_a.pk}-mis-tp-pf-hm-osv"
        msquery = self._msquery(sf)
        block0 = self._tag_filters(msquery)[0]
        for label, _, _, up_qd in block0.grouping_choices_from_grouping_results(
            msquery._get_grouping_results()
        ):
            if label == self.tag_a.name:
                self.assertIsNotNone(up_qd)
                return
        self.fail("active tag-a choice missing from owning block")
