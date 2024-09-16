import logging
import math
from urllib.parse import urlencode
from django.contrib import messages
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse
from django.views.generic import TemplateView
from zentral.contrib.inventory.models import Certificate, File
from zentral.contrib.santa.ballot_box import BallotBox, ResetNotAllowedError
from zentral.contrib.santa.models import Bundle, Configuration, MetaBundle, Rule, Target, TargetState
from zentral.contrib.santa.forms import BallotSearchForm, TargetSearchForm
from zentral.core.stores.conf import stores
from zentral.core.stores.views import EventsView, FetchEventsView, EventsStoreRedirectView
from zentral.utils.text import encode_args
from zentral.utils.views import UserPaginationMixin


logger = logging.getLogger('zentral.contrib.santa.views.targets')


class TargetsView(PermissionRequiredMixin, UserPaginationMixin, TemplateView):
    permission_required = "santa.view_target"
    template_name = "santa/targets.html"

    def dispatch(self, request, *args, **kwargs):
        self.form = TargetSearchForm(self.request.GET)
        self.form.is_valid()
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["form"] = self.form

        # current page
        try:
            page = int(self.request.GET.get("page", 1))
        except Exception:
            page = 1
        page = max(1, page)
        limit = self.get_paginate_by()
        offset = (page - 1) * limit

        # fetch results
        ctx["targets"] = self.form.results(self.request.user.username, self.request.user.email, offset, limit)

        # total
        try:
            total = ctx["targets"][0]["full_count"]
        except IndexError:
            total = 0
        ctx["target_count"] = total

        # export links
        ctx['export_links'] = []
        for fmt in ("xlsx", "zip"):
            qd = self.form.search_query_kwargs(self.request.user.username, self.request.user.email)
            qd["export_format"] = fmt
            ctx['export_links'].append((
                fmt, reverse("santa_api:targets_export") + "?" + urlencode(qd)
            ))

        # pagination
        ctx["page_num"] = page
        ctx["num_pages"] = math.ceil(total / self.get_paginate_by()) or 1
        if page > 1:
            qd = self.request.GET.copy()
            qd["page"] = page - 1
            ctx["previous_url"] = f"?{qd.urlencode()}"
            qd.pop("page")
            ctx["reset_link"] = f"?{qd.urlencode()}"
        if offset + self.get_paginate_by() < total:
            qd = self.request.GET.copy()
            qd["page"] = page + 1
            ctx["next_url"] = f"?{qd.urlencode()}"

        return ctx


class TargetView(PermissionRequiredMixin, TemplateView):
    permission_required = "santa.view_target"
    template_name = "santa/target_detail.html"
    target_type = None
    title = None
    add_rule_link_key = None
    add_rule_link_attr = "pk"
    max_ballots_preview = 10

    def get_objects(self):
        return []

    def get_rules(self):
        return (
            Rule.objects.select_related("configuration", "ruleset")
                        .filter(target__type=self.target_type, target__identifier=self.identifier)
        )

    def get_add_rule_link_qd(self):
        if not self.objects:
            return
        if not self.add_rule_link_key:
            return
        return urlencode({self.add_rule_link_key: getattr(self.objects[0], self.add_rule_link_attr)})

    def get_add_rule_links(self):
        links = []
        query_dict = self.get_add_rule_link_qd()
        if not query_dict:
            return links
        for configuration in (Configuration.objects.exclude(rule__target__type=self.target_type,
                                                            rule__target__identifier=self.identifier)
                                                   .exclude(voting_realm__isnull=False)
                                                   .order_by("name")):
            links.append((configuration.name,
                          reverse("santa:create_configuration_rule", args=(configuration.pk,)) + f"?{query_dict}"))
        return links

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data()
        self.identifier = kwargs["identifier"]
        ctx["target_type"] = self.target_type
        ctx["target_type_display"] = self.target_type.label
        ctx["title"] = self.title or ctx["target_type_display"]
        ctx["identifier"] = self.identifier

        # target
        target = get_object_or_404(Target, type=self.target_type, identifier=self.identifier)

        # ballot box
        ras = getattr(self.request, "realm_authentication_session", None)
        if ras:
            realm_user = ras.user
        else:
            realm_user = None
        ballot_box = BallotBox.for_realm_user(target, realm_user, lock_target=False, all_configurations=True)
        ctx["ballot_box"] = ballot_box

        def prepare_objects(objects):
            keys = set()
            for obj in objects:
                keys.update((k, k.replace("_", " ")) for k in obj.keys())
            keys = sorted(keys)
            return {"width": 100 / len(keys),
                    "cols": [l for _, l in keys],
                    "rows": [[obj.get(k) for k, l in keys] for obj in objects]}

        # infos
        try:
            ctx["prepared_objects"] = prepare_objects(ballot_box.target_info()["objects"])
        except (TypeError, KeyError):
            pass

        # target states
        ctx["target_states"] = []
        for configuration, target_state in ballot_box.target_states.items():
            reset_url = None
            configuration = target_state.configuration
            if ballot_box.voter.can_reset_target(configuration):
                reset_url = reverse("santa:reset_target_state", args=(configuration.pk, target_state.pk))
            ctx["target_states"].append((target_state, reset_url))
        ctx["target_states"].sort(key=lambda t: t[0].configuration.name)

        # related targets
        ctx["related_targets"] = []
        total_related_targets = 0
        for target_type in Target.Type:
            related_targets = ballot_box.related_targets.get(target_type.value, {})
            if not related_targets:
                continue
            target_infos = [
                related_targets[identifier]
                for identifier in sorted(related_targets.keys())
                if not related_targets[identifier]["self"]
            ]
            total_related_targets += len(target_infos)
            for target_info in target_infos:
                try:
                    target_info["prepared_objects"] = prepare_objects(target_info["objects"])
                except KeyError:
                    pass
            if target_infos:
                ctx["related_targets"].append((target_type.value, target_type.label, target_infos))
        ctx["total_related_targets"] = total_related_targets

        # objects
        self.objects = self.get_objects()
        ctx["objects"] = list(self.objects)
        ctx["object_count"] = len(self.objects)

        # ballots
        if self.request.user.has_perm("santa.view_ballot"):
            ctx["show_ballots"] = True
            # ballots
            ballot_search_kwargs = {"target_type": self.target_type,
                                    "target_identifier": self.identifier}
            ballot_search_kwargs_encoded = urlencode(ballot_search_kwargs)
            ballot_form = BallotSearchForm(ballot_search_kwargs)
            ballot_form.is_valid()
            top_ballots = ballot_form.results(self.request.user.username, self.request.user.email,
                                              0, self.max_ballots_preview)
            ctx["ballots"] = top_ballots[:self.max_ballots_preview]
            try:
                ctx["ballot_count"] = ctx["ballots"][0]["full_count"]
            except IndexError:
                ctx["ballot_count"] = 0
            ctx["search_ballots_link"] = reverse("santa:ballots") + "?" + ballot_search_kwargs_encoded
            # link to cast a ballot
            if (
                self.request.user.has_perm("santa.add_ballot")
                # TODO: make sure that a different vote than an existing one is possible?
                and any(
                    len(allowed_votes) > 0
                    for _, allowed_votes in ballot_box.get_configurations_allowed_votes()
                )
            ):
                ctx["cast_ballot_url"] = reverse("santa:cast_ballot") + "?" + ballot_search_kwargs_encoded
        else:
            ctx["show_ballots"] = False

        # rules
        ctx["add_rule_links"] = self.get_add_rule_links()
        if ctx["add_rule_links"]:
            ctx["show_rules"] = True
            ctx["rules"] = list(self.get_rules())
            ctx["rule_count"] = len(ctx["rules"])

        # events
        if (
            self.target_type.is_native
            and self.request.user.has_perms(EventsMixin.permission_required)
        ):
            ctx["events_url"] = reverse(f"santa:{self.target_type.lower()}_events", args=(self.identifier,))
            store_links = []
            for store in stores.iter_events_url_store_for_user("object", self.request.user):
                url = "{}?{}".format(
                    reverse(f"santa:{self.target_type.lower()}_events_store_redirect", args=(self.identifier,)),
                    urlencode({"es": store.name,
                               "tr": EventsView.default_time_range})
                )
                store_links.append((url, store.name))
            ctx["store_links"] = store_links

        return ctx


class BinaryView(TargetView):
    target_type = Target.Type.BINARY
    add_rule_link_key = "bin"

    def get_objects(self):
        return (
            File.objects.select_related("signed_by", "bundle")
                        .filter(source__module="zentral.contrib.santa",
                                source__name="Santa events",
                                sha_256=self.identifier)
        )


class BundleView(TargetView):
    target_type = Target.Type.BUNDLE

    def get_objects(self):
        return (
            Bundle.objects.select_related("target")
                          .filter(target__type=self.target_type,
                                  target__identifier=self.identifier)
        )


class MetaBundleView(TargetView):
    target_type = Target.Type.METABUNDLE

    def get_objects(self):
        return (
            MetaBundle.objects.select_related("target")
                              .filter(target__type=self.target_type,
                                      target__identifier=self.identifier)
        )


class CDHashView(TargetView):
    target_type = Target.Type.CDHASH
    add_rule_link_key = "cdhash"
    add_rule_link_attr = "cdhash"

    def get_objects(self):
        return Target.objects.get_cdhash_objects(self.identifier)


class CertificateView(TargetView):
    target_type = Target.Type.CERTIFICATE
    add_rule_link_key = "cert"

    def get_objects(self):
        return (
            Certificate.objects.select_related("signed_by")
                               .filter(sha_256=self.identifier)
        )


class TeamIDView(TargetView):
    target_type = Target.Type.TEAM_ID
    title = "Team ID"
    add_rule_link_key = "tea"
    add_rule_link_attr = "organizational_unit"

    def get_objects(self):
        return Target.objects.get_teamid_objects(self.identifier)


class SigningIDView(TargetView):
    target_type = Target.Type.SIGNING_ID
    title = "Signing ID"
    add_rule_link_key = "sig"
    add_rule_link_attr = "signing_id"

    def get_objects(self):
        return Target.objects.get_signingid_objects(self.identifier)


class EventsMixin:
    permission_required = ("santa.view_target",)
    store_method_scope = "object"
    target_type = None
    object_key = None
    identifier_key = None

    def get_object(self, **kwargs):
        self.identifier = kwargs["identifier"]
        return None

    def get_fetch_kwargs_extra(self):
        args = [self.identifier]
        if self.identifier_key:
            args.insert(0, self.identifier_key)
        return {"key": self.object_key, "val": encode_args(args)}

    def get_fetch_url(self):
        return reverse(f"santa:fetch_{self.target_type.lower()}_events", args=(self.identifier,))

    def get_redirect_url(self):
        return reverse(f"santa:{self.target_type.lower()}_events", args=(self.identifier,))

    def get_store_redirect_url(self):
        return reverse(f"santa:{self.target_type.lower()}_events_store_redirect", args=(self.identifier,))

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["target_type"] = self.target_type
        ctx["target_type_display"] = getattr(self, "target_type_display", None)
        ctx["identifier"] = self.identifier
        ctx["target_url"] = reverse(f"santa:{self.target_type.lower()}", args=(self.identifier,))
        return ctx


class BinaryEventsView(EventsMixin, EventsView):
    template_name = "santa/target_events.html"
    target_type = Target.Type.BINARY
    object_key = "file"
    identifier_key = "sha256"


class FetchBinaryEventsView(EventsMixin, FetchEventsView):
    target_type = Target.Type.BINARY
    object_key = "file"
    identifier_key = "sha256"


class BinaryEventsStoreRedirectView(EventsMixin, EventsStoreRedirectView):
    target_type = Target.Type.BINARY
    object_key = "file"
    identifier_key = "sha256"


class CDHashEventsView(EventsMixin, EventsView):
    template_name = "santa/target_events.html"
    target_type = Target.Type.CDHASH
    object_key = "file"
    identifier_key = "cdhash"


class FetchCDHashEventsView(EventsMixin, FetchEventsView):
    target_type = Target.Type.CDHASH
    object_key = "file"
    identifier_key = "cdhash"


class CDHashEventsStoreRedirectView(EventsMixin, EventsStoreRedirectView):
    target_type = Target.Type.SIGNING_ID
    object_key = "file"
    identifier_key = "cdhash"


class CertificateEventsView(EventsMixin, EventsView):
    template_name = "santa/target_events.html"
    target_type = Target.Type.CERTIFICATE
    object_key = "certificate"
    identifier_key = "sha256"


class FetchCertificateEventsView(EventsMixin, FetchEventsView):
    target_type = Target.Type.CERTIFICATE
    object_key = "certificate"
    identifier_key = "sha256"


class CertificateEventsStoreRedirectView(EventsMixin, EventsStoreRedirectView):
    target_type = Target.Type.CERTIFICATE
    object_key = "certificate"
    identifier_key = "sha256"


class SigningIDEventsView(EventsMixin, EventsView):
    template_name = "santa/target_events.html"
    target_type = Target.Type.SIGNING_ID
    object_key = "file"
    identifier_key = "apple_signing_id"


class FetchSigningIDEventsView(EventsMixin, FetchEventsView):
    target_type = Target.Type.SIGNING_ID
    object_key = "file"
    identifier_key = "apple_signing_id"


class SigningIDEventsStoreRedirectView(EventsMixin, EventsStoreRedirectView):
    target_type = Target.Type.SIGNING_ID
    object_key = "file"
    identifier_key = "apple_signing_id"


class TeamIDEventsView(EventsMixin, EventsView):
    template_name = "santa/target_events.html"
    target_type = Target.Type.TEAM_ID
    object_key = "apple_team_id"


class FetchTeamIDEventsView(EventsMixin, FetchEventsView):
    target_type = Target.Type.TEAM_ID
    object_key = "apple_team_id"


class TeamIDEventsStoreRedirectView(EventsMixin, EventsStoreRedirectView):
    target_type = Target.Type.TEAM_ID
    object_key = "apple_team_id"


class ResetTargetStateView(PermissionRequiredMixin, TemplateView):
    permission_required = "santa.view_target"
    template_name = "santa/targetstate_reset.html"

    def load_state(self, lock_target):
        self.target_state = get_object_or_404(
            TargetState.objects.select_related("configuration", "target"),
            pk=self.kwargs["pk"],
            configuration__pk=self.kwargs["configuration_pk"],
        )
        self.configuration = self.target_state.configuration
        self.target = self.target_state.target
        self.ballot_box = BallotBox.for_realm_user(
            self.target,
            self.request.realm_authentication_session.user,
            lock_target=lock_target,
            all_configurations=True,
        )

    def get_context_data(self, **kwargs):
        self.load_state(lock_target=False)
        ctx = super().get_context_data(**kwargs)
        ctx["target_state"] = self.target_state
        ctx["configuration"] = self.configuration
        ctx["target"] = self.target
        ctx["ballot_box"] = self.ballot_box
        ctx["reset_allowed"] = self.ballot_box.voter.can_reset_target(self.configuration)
        return ctx

    def post(self, request, *args, **kwargs):
        self.load_state(lock_target=True)
        try:
            self.ballot_box.reset_target_state(self.configuration)
        except ResetNotAllowedError:
            messages.error(request, "Target state reset not allowed")
        else:
            messages.info(request, "Target state reset")

            def on_commit_callback():
                self.ballot_box.post_events(self.request)

            transaction.on_commit(on_commit_callback)

        return redirect(self.target)
