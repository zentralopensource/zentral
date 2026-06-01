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
        # sf shape is identical to the pre-multi-instance encoding — values
        # live in the query dict, not in sf.
        msquery = self._msquery()
        self.assertEqual(msquery.serialize_filters(), "mbu-t-mis-tp-pf-hm-osv")

    # sf + qd parsing

    def test_bare_t_token_with_no_qd_value_is_empty_block(self):
        msquery = self._msquery("sf=mbu-t-mis-tp-pf-hm-osv")
        tag_filters = self._tag_filters(msquery)
        self.assertEqual(len(tag_filters), 1)
        self.assertIsNone(tag_filters[0].value)

    def test_legacy_single_block_url_value_in_query_dict(self):
        # ?sf=…-t-…&t=<pk> — pre-multi-instance shape, also the new format
        # for a single block. Must work without any translation or redirect.
        msquery = self._msquery(f"sf=mbu-t-mis-tp-pf-hm-osv&t={self.tag_a.pk}")
        tag_filters = self._tag_filters(msquery)
        self.assertEqual(len(tag_filters), 1)
        self.assertEqual(tag_filters[0].value, str(self.tag_a.pk))
        self.assertEqual(msquery.count(), 2)  # serials 0 and 1 have tag-a
        self.assertFalse(msquery._redirect)

    def test_no_tag_value_in_query_dict(self):
        msquery = self._msquery(f"sf=mbu-t-mis-tp-pf-hm-osv&t={TagFilter.none_value}")
        tag_filters = self._tag_filters(msquery)
        self.assertEqual(tag_filters[0].value, TagFilter.none_value)
        # only serial 2 has no tags
        self.assertEqual(msquery.count(), 1)
        self.assertFalse(msquery._redirect)

    def test_invalid_value_in_query_dict_clears_and_redirects(self):
        msquery = self._msquery("sf=mbu-t-mis-tp-pf-hm-osv&t=notanint")
        tag_filters = self._tag_filters(msquery)
        self.assertEqual(len(tag_filters), 1)
        self.assertIsNone(tag_filters[0].value)
        self.assertTrue(msquery._redirect)
        # the bad key was dropped from query_dict so the redirect URL stays clean
        self.assertNotIn("t=notanint", msquery.redirect_url())

    # position-aware query kwargs

    def test_first_block_uses_bare_t_kwarg(self):
        msquery = self._msquery("sf=mbu-t-mis-tp-pf-hm-osv")
        self.assertEqual(self._tag_filters(msquery)[0].get_query_kwarg(), "t")

    def test_subsequent_blocks_use_numbered_kwargs(self):
        msquery = self._msquery("sf=mbu-t-t-t-mis-tp-pf-hm-osv")
        kwargs = [f.get_query_kwarg() for f in self._tag_filters(msquery)]
        self.assertEqual(kwargs, ["t", "t1", "t2"])

    def test_second_block_value_lives_under_t1(self):
        msquery = self._msquery(
            f"sf=mbu-t-t-mis-tp-pf-hm-osv&t={self.tag_a.pk}&t1={self.tag_b.pk}"
        )
        tag_filters = self._tag_filters(msquery)
        self.assertEqual(tag_filters[0].value, str(self.tag_a.pk))
        self.assertEqual(tag_filters[1].value, str(self.tag_b.pk))

    # lateral-join shape (carried over from the SQL guard fix)

    def test_constrained_block_pushes_tag_id_into_lateral(self):
        msquery = self._msquery(f"sf=mbu-t-mis-tp-pf-hm-osv&t={self.tag_a.pk}")
        tag_filter = self._tag_filters(msquery)[0]
        (lateral, lateral_args), _ = tag_filter.joins()
        self.assertIn(f"t{tag_filter.idx} on TRUE", lateral)
        self.assertIn("inventory_tag.id = %s", lateral)
        self.assertEqual(lateral_args, [str(self.tag_a.pk)])

    def test_unconstrained_block_keeps_open_lateral(self):
        msquery = self._msquery("sf=mbu-t-mis-tp-pf-hm-osv")
        tag_filter = self._tag_filters(msquery)[0]
        (lateral, lateral_args), _ = tag_filter.joins()
        self.assertNotIn("inventory_tag.id = %s", lateral)
        self.assertEqual(lateral_args, [])

    def test_no_tag_block_does_not_push_into_lateral(self):
        msquery = self._msquery(f"sf=mbu-t-mis-tp-pf-hm-osv&t={TagFilter.none_value}")
        tag_filter = self._tag_filters(msquery)[0]
        (lateral, lateral_args), _ = tag_filter.joins()
        self.assertNotIn("inventory_tag.id = %s", lateral)
        self.assertEqual(lateral_args, [])
        self.assertIn(f"t{tag_filter.idx}.id is null", list(tag_filter.wheres()))

    def test_constrained_block_args_carried_to_grouping_query(self):
        msquery = self._msquery(
            f"sf=mbu-t-t-mis-tp-pf-hm-osv&t={self.tag_a.pk}&t1={self.tag_b.pk}"
        )
        query, args = msquery._build_grouping_query_with_args()
        self.assertEqual(query.count("inventory_tag.id = %s"), 2)
        self.assertIn(str(self.tag_a.pk), args)
        self.assertIn(str(self.tag_b.pk), args)

    def test_constrained_block_drops_outer_equality_clause(self):
        msquery = self._msquery(f"sf=mbu-t-mis-tp-pf-hm-osv&t={self.tag_a.pk}")
        tag_filter = self._tag_filters(msquery)[0]
        wheres = list(tag_filter.wheres())
        self.assertEqual(wheres, [f"t{tag_filter.idx}.id is not null"])
        self.assertEqual(list(tag_filter.where_args()), [])

    # multi-block AND semantics

    def test_two_blocks_both_with_values_intersect(self):
        msquery = self._msquery(
            f"sf=mbu-t-t-mis-tp-pf-hm-osv&t={self.tag_a.pk}&t1={self.tag_b.pk}"
        )
        self.assertEqual(len(self._tag_filters(msquery)), 2)
        # only serial 0 has BOTH tag-a and tag-b
        self.assertEqual(msquery.count(), 1)

    def test_two_blocks_no_intersection(self):
        # tag-b is on serial 0, tag-c on no machine
        msquery = self._msquery(
            f"sf=mbu-t-t-mis-tp-pf-hm-osv&t={self.tag_b.pk}&t1={self.tag_c.pk}"
        )
        self.assertEqual(msquery.count(), 0)

    def test_two_blocks_one_empty_acts_like_single_block(self):
        # block 0 picks tag-a, block 1 has no value → matches all machines with tag-a
        msquery = self._msquery(f"sf=mbu-t-t-mis-tp-pf-hm-osv&t={self.tag_a.pk}")
        self.assertEqual(msquery.count(), 2)

    # block removal — sf token dropped and trailing kwargs renumbered

    def test_remove_first_block_renames_trailing_keys(self):
        # Two blocks; click the trash on block 0. The kept block's value
        # (tag_b) was at `t1` and must migrate to `t` so the next request
        # parses it as the surviving first block.
        msquery = self._msquery(
            f"sf=mbu-t-t-mis-tp-pf-hm-osv&t={self.tag_a.pk}&t1={self.tag_b.pk}"
        )
        block0 = self._tag_filters(msquery)[0]
        for f, _, f_r_link, _ in msquery.grouping_links():
            if f is block0:
                self.assertIsNotNone(f_r_link)
                next_qd = QueryDict(f_r_link.lstrip("?"), mutable=True)
                # exactly one bare `t` remains in sf
                self.assertEqual(next_qd["sf"], "mbu-t-mis-tp-pf-hm-osv")
                # tag_b migrated from t1 to t; tag_a is gone
                self.assertEqual(next_qd.get("t"), str(self.tag_b.pk))
                self.assertNotIn("t1", next_qd)
                return
        self.fail("first tag block not found in grouping_links")

    def test_remove_last_block_leaves_first_block_intact(self):
        msquery = self._msquery(
            f"sf=mbu-t-t-mis-tp-pf-hm-osv&t={self.tag_a.pk}&t1={self.tag_b.pk}"
        )
        block1 = self._tag_filters(msquery)[1]
        for f, _, f_r_link, _ in msquery.grouping_links():
            if f is block1:
                self.assertIsNotNone(f_r_link)
                next_qd = QueryDict(f_r_link.lstrip("?"), mutable=True)
                self.assertEqual(next_qd["sf"], "mbu-t-mis-tp-pf-hm-osv")
                self.assertEqual(next_qd.get("t"), str(self.tag_a.pk))
                self.assertNotIn("t1", next_qd)
                return
        self.fail("second tag block not found in grouping_links")

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

    def test_canonical_query_dict_carries_values_in_query_dict(self):
        msquery = self._msquery(
            f"sf=mbu-t-t-mis-tp-pf-hm-osv&t={self.tag_a.pk}&t1={self.tag_b.pk}"
        )
        qd = msquery.get_canonical_query_dict()
        # values are in the query dict, not in sf
        self.assertEqual(qd["t"], str(self.tag_a.pk))
        self.assertEqual(qd["t1"], str(self.tag_b.pk))
        self.assertNotIn(f"t.{self.tag_a.pk}", qd["sf"])
        self.assertNotIn(f"t.{self.tag_b.pk}", qd["sf"])

    # toggling

    def test_grouping_choice_down_link_sets_block_value_in_qd(self):
        msquery = self._msquery("sf=mbu-t-mis-tp-pf-hm-osv")
        block0 = self._tag_filters(msquery)[0]
        for f, choices in msquery.grouping_choices():
            if f is not block0:
                continue
            for label, _, down_qd, _ in choices:
                if label == self.tag_a.name:
                    self.assertIsNotNone(down_qd)
                    self.assertEqual(down_qd["t"], str(self.tag_a.pk))
                    return
        self.fail("tag-a choice not found")

    def test_grouping_choice_down_link_for_second_block_uses_t1(self):
        msquery = self._msquery(f"sf=mbu-t-t-mis-tp-pf-hm-osv&t={self.tag_a.pk}")
        block1 = self._tag_filters(msquery)[1]
        for f, choices in msquery.grouping_choices():
            if f is not block1:
                continue
            for label, _, down_qd, _ in choices:
                if label == self.tag_b.name:
                    self.assertIsNotNone(down_qd)
                    # second block's pick lands in t1, leaving block 0 alone
                    self.assertEqual(down_qd["t1"], str(self.tag_b.pk))
                    self.assertEqual(down_qd["t"], str(self.tag_a.pk))
                    return
        self.fail("tag-b choice not found in second block")

    def test_grouping_choice_up_link_clears_block_value(self):
        msquery = self._msquery(f"sf=mbu-t-mis-tp-pf-hm-osv&t={self.tag_a.pk}")
        block0 = self._tag_filters(msquery)[0]
        for f, choices in msquery.grouping_choices():
            if f is not block0:
                continue
            for label, _, _, up_qd in choices:
                if label == self.tag_a.name:
                    self.assertIsNotNone(up_qd)
                    # value cleared from query dict; sf token remains
                    self.assertNotIn("t", up_qd)
                    self.assertEqual(up_qd["sf"], "mbu-t-mis-tp-pf-hm-osv")
                    return
        self.fail("active tag-a choice not found")

    # fetch shows tags

    def test_fetch_accumulates_tags_across_blocks(self):
        msquery = self._msquery(
            f"sf=mbu-t-t-mis-tp-pf-hm-osv&t={self.tag_a.pk}&t1={self.tag_b.pk}"
        )
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
        msquery = self._msquery(f"sf=mbu-t-mis-tp-pf-hm-osv&t={self.tag_a.pk}")
        self.assertEqual(self._tag_filters(msquery)[0].title, "Tags · tag-a")

    def test_title_no_tag_for_none_value(self):
        msquery = self._msquery(f"sf=mbu-t-mis-tp-pf-hm-osv&t={TagFilter.none_value}")
        self.assertEqual(self._tag_filters(msquery)[0].title, "Tags · No tag")

    def test_title_falls_back_when_tag_missing(self):
        # int-castable pk that doesn't exist in DB — passes ctor validation
        # but Tag.objects.get raises, so title falls back to "Tags".
        msquery = self._msquery("sf=mbu-t-mis-tp-pf-hm-osv&t=999999999")
        self.assertEqual(self._tag_filters(msquery)[0].title, "Tags")

    # sibling exclusion

    def test_other_block_choices_skip_tag_picked_in_first_block(self):
        msquery = self._msquery(f"sf=mbu-t-t-mis-tp-pf-hm-osv&t={self.tag_a.pk}")
        block0, block1 = self._tag_filters(msquery)
        block0_labels = {label for label, _, _, _ in block0.grouping_choices_from_grouping_results(
            msquery._get_grouping_results()
        )}
        self.assertIn(self.tag_a.name, block0_labels)
        # block 1 sees tag-a in raw results (machines with tag-a) but the row
        # is suppressed because tag-a is already pinned in block 0
        block1_labels = {label for label, _, _, _ in block1.grouping_choices_from_grouping_results(
            msquery._get_grouping_results()
        )}
        self.assertNotIn(self.tag_a.name, block1_labels)

    def test_block_keeps_its_own_value_visible_when_other_block_unselected(self):
        msquery = self._msquery(f"sf=mbu-t-mis-tp-pf-hm-osv&t={self.tag_a.pk}")
        block0 = self._tag_filters(msquery)[0]
        for label, _, _, up_qd in block0.grouping_choices_from_grouping_results(
            msquery._get_grouping_results()
        ):
            if label == self.tag_a.name:
                self.assertIsNotNone(up_qd)
                return
        self.fail("active tag-a choice missing from owning block")

    # force_filter guard

    def test_force_filter_rejects_multi_instance_class(self):
        msquery = self._msquery()
        with self.assertRaisesRegex(ValueError, "multi_instance"):
            msquery.force_filter(TagFilter, value=str(self.tag_a.pk))
