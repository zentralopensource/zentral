import logging
import math
from urllib.parse import urlencode
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.urls import reverse
from django.views.generic import TemplateView
from zentral.contrib.inventory.models import Certificate, File
from zentral.contrib.santa.models import Bundle, Configuration, Rule, Target
from zentral.contrib.santa.forms import TargetSearchForm
from zentral.core.events.utils import encode_args
from zentral.core.stores import stores
from zentral.core.stores.views import EventsView, FetchEventsView, EventsStoreRedirectView


logger = logging.getLogger('zentral.contrib.santa.views.targets')


class TargetsView(PermissionRequiredMixin, TemplateView):
    permission_required = "santa.view_target"
    template_name = "santa/targets.html"
    paginate_by = 10

    def dispatch(self, request, *args, **kwargs):
        self.form = TargetSearchForm(self.request.GET)
        self.form.is_valid()
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["form"] = self.form

        # current page
        try:
            page = int(self.request.GET.get("page", 1))
        except Exception:
            page = 1
        page = max(1, page)
        offset = (page - 1) * self.paginate_by

        # fetch results
        ctx["targets"] = Target.objects.search(q=self.form.cleaned_data.get("q"),
                                               target_type=self.form.cleaned_data.get("target_type"),
                                               offset=offset, limit=self.paginate_by)

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
        ctx["num_pages"] = math.ceil(total / self.paginate_by) or 1
        if page > 1:
            qd = self.request.GET.copy()
            qd["page"] = page - 1
            ctx["previous_url"] = f"?{qd.urlencode()}"
            qd.pop("page")
            ctx["reset_link"] = f"?{qd.urlencode()}"
        if offset + self.paginate_by < total:
            qd = self.request.GET.copy()
            qd["page"] = page + 1
            ctx["next_url"] = f"?{qd.urlencode()}"

        return ctx


class TargetView(PermissionRequiredMixin, TemplateView):
    permission_required = "santa.view_target"
    template_name = "santa/target_detail.html"
    target_type = None
    add_rule_link_key = None

    def get_objects(self):
        return []

    def get_add_rule_link_qd(self):
        if not self.objects:
            return
        return urlencode({self.add_rule_link_key: self.objects[0].pk})

    def get_rules(self):
        return (
            Rule.objects.select_related("configuration", "ruleset")
                        .filter(target__type=self.target_type, target__sha256=self.sha256)
        )

    def get_add_rule_links(self):
        links = []
        query_dict = self.get_add_rule_link_qd()
        if not query_dict:
            return links
        for configuration in (Configuration.objects.exclude(rule__target__type=self.target_type,
                                                            rule__target__sha256=self.sha256)
                                                   .order_by("name")):
            links.append((configuration.name,
                          reverse("santa:create_configuration_rule", args=(configuration.pk,)) + f"?{query_dict}"))
        return links

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data()
        self.sha256 = kwargs["sha256"]
        ctx["setup"] = True
        ctx["target_type"] = self.target_type
        ctx["sha256"] = self.sha256

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
            ctx["events_url"] = reverse(f"santa:{self.target_type.lower()}_events", args=(self.sha256,))
            store_links = []
            for store in stores.iter_events_url_store_for_user("object", self.request.user):
                url = "{}?{}".format(
                    reverse(f"santa:{self.target_type.lower()}_events_store_redirect", args=(self.sha256,)),
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
                                sha_256=self.sha256)
        )


class BundleView(TargetView):
    target_type = Target.BUNDLE
    add_rule_link_key = "bun"

    def get_objects(self):
        return (
            Bundle.objects.select_related("target")
                          .filter(target__type=self.target_type,
                                  target__sha256=self.sha256)
        )


class CertificateView(TargetView):
    target_type = Target.CERTIFICATE
    add_rule_link_key = "cert"

    def get_objects(self):
        return (
            Certificate.objects.select_related("signed_by")
                               .filter(sha_256=self.sha256)
        )


class EventsMixin:
    permission_required = "santa.view_target"
    store_method_scope = "object"
    target_type = None
    object_key = None

    def get_object(self, **kwargs):
        self.sha256 = kwargs["sha256"]
        return None

    def get_fetch_kwargs_extra(self):
        return {"key": self.object_key, "val": encode_args(("sha256", self.sha256))}

    def get_fetch_url(self):
        return reverse(f"santa:fetch_{self.target_type.lower()}_events", args=(self.sha256,))

    def get_redirect_url(self):
        return reverse(f"santa:{self.target_type.lower()}_events", args=(self.sha256,))

    def get_store_redirect_url(self):
        return reverse(f"santa:{self.target_type.lower()}_events_store_redirect", args=(self.sha256,))

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["target_type"] = self.target_type
        ctx["sha256"] = self.sha256
        ctx["target_url"] = reverse(f"santa:{self.target_type.lower()}", args=(self.sha256,))
        return ctx


class BinaryEventsView(EventsMixin, EventsView):
    template_name = "santa/target_events.html"
    target_type = Target.BINARY
    object_key = "file"


class FetchBinaryEventsView(EventsMixin, FetchEventsView):
    target_type = Target.BINARY
    object_key = "file"


class BinaryEventsStoreRedirectView(EventsMixin, EventsStoreRedirectView):
    target_type = Target.BINARY
    object_key = "file"


class BundleEventsView(EventsMixin, EventsView):
    template_name = "santa/target_events.html"
    target_type = Target.BUNDLE
    object_key = "bundle"


class FetchBundleEventsView(EventsMixin, FetchEventsView):
    target_type = Target.BUNDLE
    object_key = "bundle"


class BundleEventsStoreRedirectView(EventsMixin, EventsStoreRedirectView):
    target_type = Target.BUNDLE
    object_key = "bundle"


class CertificateEventsView(EventsMixin, EventsView):
    template_name = "santa/target_events.html"
    target_type = Target.CERTIFICATE
    object_key = "certificate"


class FetchCertificateEventsView(EventsMixin, FetchEventsView):
    target_type = Target.CERTIFICATE
    object_key = "certificate"


class CertificateEventsStoreRedirectView(EventsMixin, EventsStoreRedirectView):
    target_type = Target.CERTIFICATE
    object_key = "certificate"
