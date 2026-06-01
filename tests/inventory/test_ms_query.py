from django.http import QueryDict
from django.test import TestCase
from django.utils.crypto import get_random_string

from zentral.contrib.inventory.models import MachineSnapshotCommit, MachineTag, Tag, Taxonomy
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
        # Extra tag on serial 0 used by the "show unmatched tags" test —
        # serial 0 has it but no filter ever matches on it.
        cls.tag_d = Tag.objects.create(name="tag-d")
        # serial 0: a + b + d
        MachineTag.objects.create(serial_number=cls.serials[0], tag=cls.tag_a)
        MachineTag.objects.create(serial_number=cls.serials[0], tag=cls.tag_b)
        MachineTag.objects.create(serial_number=cls.serials[0], tag=cls.tag_d)
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

    def test_available_filters_disables_tags_when_an_empty_block_exists(self):
        # An empty block is a free slot — stacking another would just add
        # an unconstrained lateral join. The entry stays visible so users
        # see Tags is a known filter, but the link is None so the template
        # renders it disabled.
        msquery = self._msquery("sf=mbu-t-mis-tp-pf-hm-osv")
        entries = dict(msquery.available_filters())
        self.assertIn("Tags", entries)
        self.assertIsNone(entries["Tags"])

    def test_available_filters_offers_tags_once_existing_block_has_value(self):
        msquery = self._msquery(f"sf=mbu-t-mis-tp-pf-hm-osv&t={self.tag_a.pk}")
        entries = dict(msquery.available_filters())
        self.assertIn("Tags", entries)
        self.assertIsNotNone(entries["Tags"])

    def test_add_filter_link_inserts_new_t_adjacent_to_existing(self):
        # Canonical sf groups same-class tokens together — the new `t` must
        # be inserted next to the existing one, not appended at the end.
        msquery = self._msquery(f"sf=mbu-t-mis-tp-pf-hm-osv&t={self.tag_a.pk}")
        for title, link in msquery.available_filters():
            if title == "Tags":
                self.assertIn("sf=mbu-t-t-mis-tp-pf-hm-osv", link)
                return
        self.fail("Tags entry missing from available_filters")

    # canonical sf rigidity

    def test_non_contiguous_t_tokens_trigger_redirect(self):
        # `-t-…-t` with non-`t` tokens in between is non-canonical. The
        # filter behavior is the same (multi_instance parsing is position-
        # insensitive) but the user should land on the canonical URL.
        msquery = self._msquery("sf=mbu-t-mis-tp-pf-hm-osv-t")
        self.assertEqual(len(self._tag_filters(msquery)), 2)
        self.assertTrue(msquery._redirect)

    def test_non_contiguous_redirect_url_groups_t_tokens(self):
        msquery = self._msquery("sf=mbu-t-mis-tp-pf-hm-osv-t")
        redirect = msquery.redirect_url()
        self.assertIsNotNone(redirect)
        self.assertIn("sf=mbu-t-t-mis-tp-pf-hm-osv", redirect)
        # parsing the canonical target lands on a stable state
        next_qd = QueryDict(redirect.lstrip("?"), mutable=True)
        next_msquery = MSQuery(next_qd)
        self.assertFalse(next_msquery._redirect)
        self.assertEqual(len(self._tag_filters(next_msquery)), 2)

    def test_contiguous_t_tokens_do_not_redirect(self):
        msquery = self._msquery("sf=mbu-t-t-mis-tp-pf-hm-osv")
        self.assertFalse(msquery._redirect)

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

    def test_fetch_shows_full_machine_tag_set(self):
        # Serial 0 has tag-a, tag-b, tag-d. Filtering on just tag-a should
        # still surface every tag of the machine in the rendered row —
        # the row reflects the machine, not the filter. Tags come back
        # sorted by str(tag) so the row order is deterministic.
        msquery = self._msquery(f"sf=mbu-t-mis-tp-pf-hm-osv&t={self.tag_a.pk}")
        for serial_number, machine_snapshots in msquery.fetch():
            if serial_number != self.serials[0]:
                continue
            for ms in machine_snapshots:
                tags = ms.get("tags", [])
                self.assertEqual([t.name for t in tags], ["tag-a", "tag-b", "tag-d"])
                # All entries are Tag model instances — the template tag
                # and the export consume them directly via str()/attrs.
                for t in tags:
                    self.assertIsInstance(t, Tag)
            return
        self.fail("expected serial 0 in result set")

    def test_fetch_taxonomy_loaded_on_tag(self):
        taxonomy = Taxonomy.objects.create(name="env")
        tag = Tag.objects.create(name="prod", taxonomy=taxonomy)
        MachineTag.objects.create(serial_number=self.serials[1], tag=tag)
        msquery = self._msquery(f"sf=mbu-t-mis-tp-pf-hm-osv&t={tag.pk}")
        for serial_number, machine_snapshots in msquery.fetch():
            if serial_number != self.serials[1]:
                continue
            by_name = {t.name: t for ms in machine_snapshots for t in ms.get("tags", [])}
            self.assertIn("prod", by_name)
            # taxonomy was select_related — no extra query when accessed
            with self.assertNumQueries(0):
                self.assertEqual(by_name["prod"].taxonomy.name, "env")
            # str(tag) is what the template's inventory_tag tag and the
            # export both consume — matches Tag.__str__: "taxonomy: name".
            self.assertEqual(str(by_name["prod"]), "env: prod")
            return
        self.fail("expected serial 1 in result set")

    def test_export_tag_column_matches_ui_via_str_tag(self):
        # The export pipes str(tag), the same string the UI badge renders —
        # so taxonomied tags appear as "taxonomy: name". This is a breaking
        # change vs. the previous export (which only emitted the bare name,
        # or "mbu/name" for MBU-anchored tags), traded for consistency
        # between what users see on screen and in their exports. Tags are
        # sorted case-insensitively by str(tag), so "env: prod" (e) lands
        # before tag-a/b/d (t).
        taxonomy = Taxonomy.objects.create(name="env")
        prod_tag = Tag.objects.create(name="prod", taxonomy=taxonomy)
        MachineTag.objects.create(serial_number=self.serials[0], tag=prod_tag)
        msquery = self._msquery(f"sf=mbu-t-mis-tp-pf-hm-osv&t={self.tag_a.pk}")
        machines_sheet = next(iter(msquery.export_sheets_data()))
        _, headers, rows = machines_sheet
        tag_col = headers.index("Tags")
        row_by_serial = {row[2]: row for row in rows}  # SN is column index 2
        self.assertEqual(
            row_by_serial[self.serials[0]][tag_col],
            "env: prod|tag-a|tag-b|tag-d",
        )

    def test_fetch_paginate_false_streams_in_chunks(self):
        # Belt-and-suspenders for the export path (paginate=False). Lower
        # itersize so we actually cross the batch boundary with our small
        # fixture — exercises the multi-batch enrichment code.
        msquery = self._msquery(f"sf=mbu-t-mis-tp-pf-hm-osv&t={self.tag_a.pk}")
        msquery.itersize = 1
        seen_by_serial = {}
        for serial_number, machine_snapshots in msquery.fetch(paginate=False):
            seen_by_serial[serial_number] = {
                t.name for ms in machine_snapshots for t in ms.get("tags", [])
            }
        self.assertEqual(set(seen_by_serial), {self.serials[0], self.serials[1]})
        self.assertEqual(seen_by_serial[self.serials[0]], {"tag-a", "tag-b", "tag-d"})
        self.assertEqual(seen_by_serial[self.serials[1]], {"tag-a"})

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

    # coverage backfill for branches the main behavior tests don't reach

    def test_title_includes_mbu_when_tag_has_mbu(self):
        from zentral.contrib.inventory.models import MetaBusinessUnit
        mbu = MetaBusinessUnit.objects.create(name="dept-x")
        tag = Tag.objects.create(name="ops", meta_business_unit=mbu)
        msquery = self._msquery(f"sf=mbu-t-mis-tp-pf-hm-osv&t={tag.pk}")
        self.assertEqual(self._tag_filters(msquery)[0].title, "Tags · dept-x/ops")

    def test_invalid_value_with_immutable_query_dict_does_not_crash(self):
        # request.GET is immutable. A garbage `t=` value must coerce to
        # empty and request a redirect without raising on the QD pop.
        qd = QueryDict("sf=mbu-t-mis-tp-pf-hm-osv&t=garbage")  # immutable by default
        msquery = MSQuery(qd)
        self.assertIsNone(self._tag_filters(msquery)[0].value)
        self.assertTrue(msquery._redirect)

    def test_canonical_insert_position_appends_unknown_class(self):
        # _canonical_insert_position falls back to "append" when the filter's
        # class is in neither default_filters nor extra_filters.
        from zentral.contrib.inventory.utils.msquery import BundleFilter
        msquery = self._msquery()
        bundle_filter = BundleFilter(msquery, len(msquery.filters), msquery.query_dict, bundle_name="x")
        pos = msquery._canonical_insert_position(list(msquery.filters), bundle_filter)
        self.assertEqual(pos, len(msquery.filters))

    def test_canonical_insert_position_lands_before_higher_class_filter(self):
        # Drop pf from sf, then re-add via available_filters. The new
        # Platforms entry must land between tp and hm — exercises the loop
        # in _canonical_insert_position that returns the index of the
        # first existing filter with a higher class order.
        msquery = self._msquery("sf=mbu-t-mis-tp-hm-osv")
        for title, link in msquery.available_filters():
            if title == "Platforms":
                self.assertIn("sf=mbu-t-mis-tp-pf-hm-osv", link)
                return
        self.fail("Platforms entry missing from available_filters")

    def test_fetch_without_tag_filter_skips_bulk_tag_query(self):
        # An sf without `t` skips the default TagFilter. The fetch path
        # must not run the MachineTag bulk query — only the main fetching
        # query — and must not attach a tags field.
        msquery = self._msquery("sf=mbu-mis-tp-pf-hm-osv")
        self.assertEqual(self._tag_filters(msquery), [])
        with self.assertNumQueries(1):
            machines = list(msquery.fetch())
        self.assertEqual(len(machines), 3)
        for _, machine_snapshots in machines:
            for ms in machine_snapshots:
                self.assertNotIn("tags", ms)

    def test_fetch_tags_by_serial_empty_set_returns_empty_dict(self):
        msquery = self._msquery()
        with self.assertNumQueries(0):
            self.assertEqual(msquery._fetch_tags_by_serial(set()), {})
