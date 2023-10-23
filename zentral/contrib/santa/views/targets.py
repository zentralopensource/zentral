import logging
import math
from urllib.parse import urlencode
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.urls import reverse
from django.views.generic import TemplateView
from zentral.contrib.inventory.models import Certificate, File
from zentral.contrib.santa.models import Bundle, Configuration, Rule, Target
from zentral.contrib.santa.forms import TargetSearchForm
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
        offset = (page - 1) * self.get_paginate_by()

        # fetch results
        ctx["targets"] = Target.objects.search(q=self.form.cleaned_data.get("q"),
                                               target_type=self.form.cleaned_data.get("target_type"),
                                               offset=offset, limit=self.get_paginate_by())

        # total
        try:
            total = ctx["targets"][0]["full_count"]
        except IndexError:
            total = 0
        ctx["target_count"] = total

        # export links
        ctx['export_links'] = []
        for fmt in ("xlsx", "zip"):
            qd = self.request.GET.copy()
            qd.pop("page", None)
            qd["export_format"] = fmt
            ctx['export_links'].append((
                fmt, f'{reverse("santa_api:targets_export")}?{qd.urlencode()}'
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

    def get_objects(self):
        return []

    def get_add_rule_link_qd(self):
        if not self.objects:
            return
        return urlencode({self.add_rule_link_key: getattr(self.objects[0], self.add_rule_link_attr)})

    def get_rules(self):
        return (
            Rule.objects.select_related("configuration", "ruleset")
                        .filter(target__type=self.target_type, target__identifier=self.identifier)
        )

    def get_add_rule_links(self):
        links = []
        query_dict = self.get_add_rule_link_qd()
        if not query_dict:
            return links
        for configuration in (Configuration.objects.exclude(rule__target__type=self.target_type,
                                                            rule__target__identifier=self.identifier)
                                                   .order_by("name")):
            links.append((configuration.name,
                          reverse("santa:create_configuration_rule", args=(configuration.pk,)) + f"?{query_dict}"))
        return links

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data()
        self.identifier = kwargs["identifier"]
        ctx["target_type"] = self.target_type
        if self.target_type == Target.TEAM_ID:
            ctx["target_type_display"] = "Team ID"
        elif self.target_type == Target.SIGNING_ID:
            ctx["target_type_display"] = "Signing ID"
        else:
            ctx["target_type_display"] = self.target_type.title()
        ctx["title"] = self.title or ctx["target_type_display"]
        ctx["identifier"] = self.identifier

        # objects
        self.objects = self.get_objects()
        ctx["objects"] = list(self.objects)
        ctx["object_count"] = len(self.objects)

        # rules
        ctx["rules"] = list(self.get_rules())
        ctx["rule_count"] = len(ctx["rules"])
        ctx["add_rule_links"] = self.get_add_rule_links()

        # events
        if self.request.user.has_perms(EventsMixin.permission_required):
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
    target_type = Target.BINARY
    add_rule_link_key = "bin"

    def get_objects(self):
        return (
            File.objects.select_related("signed_by", "bundle")
                        .filter(source__module="zentral.contrib.santa",
                                source__name="Santa events",
                                sha_256=self.identifier)
        )


class BundleView(TargetView):
    target_type = Target.BUNDLE
    add_rule_link_key = "bun"

    def get_objects(self):
        return (
            Bundle.objects.select_related("target")
                          .filter(target__type=self.target_type,
                                  target__identifier=self.identifier)
        )


class CertificateView(TargetView):
    target_type = Target.CERTIFICATE
    add_rule_link_key = "cert"

    def get_objects(self):
        return (
            Certificate.objects.select_related("signed_by")
                               .filter(sha_256=self.identifier)
        )


class TeamIDView(TargetView):
    target_type = Target.TEAM_ID
    title = "Team ID"
    add_rule_link_key = "tea"
    add_rule_link_attr = "organizational_unit"

    def get_objects(self):
        return Target.objects.get_teamid_objects(self.identifier)


class SigningIDView(TargetView):
    target_type = Target.SIGNING_ID
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
    target_type = Target.BINARY
    target_type_display = "Binary"
    object_key = "file"
    identifier_key = "sha256"


class FetchBinaryEventsView(EventsMixin, FetchEventsView):
    target_type = Target.BINARY
    object_key = "file"
    identifier_key = "sha256"


class BinaryEventsStoreRedirectView(EventsMixin, EventsStoreRedirectView):
    target_type = Target.BINARY
    object_key = "file"
    identifier_key = "sha256"


class BundleEventsView(EventsMixin, EventsView):
    template_name = "santa/target_events.html"
    target_type = Target.BUNDLE
    target_type_display = "Bundle"
    object_key = "bundle"
    identifier_key = "sha256"


class FetchBundleEventsView(EventsMixin, FetchEventsView):
    target_type = Target.BUNDLE
    object_key = "bundle"
    identifier_key = "sha256"


class BundleEventsStoreRedirectView(EventsMixin, EventsStoreRedirectView):
    target_type = Target.BUNDLE
    object_key = "bundle"
    identifier_key = "sha256"


class CertificateEventsView(EventsMixin, EventsView):
    template_name = "santa/target_events.html"
    target_type = Target.CERTIFICATE
    target_type_display = "Certificate"
    object_key = "certificate"
    identifier_key = "sha256"


class FetchCertificateEventsView(EventsMixin, FetchEventsView):
    target_type = Target.CERTIFICATE
    object_key = "certificate"
    identifier_key = "sha256"


class CertificateEventsStoreRedirectView(EventsMixin, EventsStoreRedirectView):
    target_type = Target.CERTIFICATE
    object_key = "certificate"
    identifier_key = "sha256"


class TeamIDEventsView(EventsMixin, EventsView):
    template_name = "santa/target_events.html"
    target_type = Target.TEAM_ID
    target_type_display = "Team ID"
    object_key = "apple_team_id"


class FetchTeamIDEventsView(EventsMixin, FetchEventsView):
    target_type = Target.TEAM_ID
    object_key = "apple_team_id"


class TeamIDEventsStoreRedirectView(EventsMixin, EventsStoreRedirectView):
    target_type = Target.TEAM_ID
    object_key = "apple_team_id"


class SigningIDEventsView(EventsMixin, EventsView):
    template_name = "santa/target_events.html"
    target_type = Target.SIGNING_ID
    target_type_display = "Signing ID"
    object_key = "signing_id"


class FetchSigningIDEventsView(EventsMixin, FetchEventsView):
    target_type = Target.SIGNING_ID
    object_key = "signing_id"


class SigningIDEventsStoreRedirectView(EventsMixin, EventsStoreRedirectView):
    target_type = Target.SIGNING_ID
    object_key = "signing_id"
