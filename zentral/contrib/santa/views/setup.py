import logging
from urllib.parse import urlencode
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.db import transaction
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse
from django.views.generic import DetailView, ListView, TemplateView, View
from django.views.generic.edit import CreateView, DeleteView, FormView, UpdateView
from zentral.contrib.inventory.forms import EnrollmentSecretForm
from zentral.contrib.inventory.models import Certificate, File
from zentral.contrib.santa.events import post_santa_rule_update_event
from zentral.contrib.santa.forms import (BinarySearchForm, BundleSearchForm, CertificateSearchForm, TeamIDSearchForm,
                                         ConfigurationForm, EnrollmentForm, RuleForm, RuleSearchForm, UpdateRuleForm)
from zentral.contrib.santa.models import Bundle, Configuration, Enrollment, Rule, Target
from zentral.contrib.santa.utils import build_configuration_plist, build_configuration_profile
from zentral.core.stores.conf import frontend_store, stores
from zentral.core.stores.views import EventsView, FetchEventsView, EventsStoreRedirectView
from zentral.utils.text import encode_args


logger = logging.getLogger('zentral.contrib.santa.views.setup')


class ConfigurationListView(PermissionRequiredMixin, TemplateView):
    permission_required = "santa.view_configuration"
    template_name = "santa/configuration_list.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["configurations"] = Configuration.objects.summary()
        ctx["configuration_count"] = len(ctx["configurations"])
        return ctx


class CreateConfigurationView(PermissionRequiredMixin, CreateView):
    permission_required = "santa.add_configuration"
    model = Configuration
    form_class = ConfigurationForm

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        return ctx


class ConfigurationView(PermissionRequiredMixin, DetailView):
    permission_required = "santa.view_configuration"
    model = Configuration

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        enrollments = list(self.object.enrollment_set.select_related("secret").all().order_by("id"))
        ctx["enrollments"] = enrollments
        ctx["enrollments_count"] = len(enrollments)
        ctx["rules_count"] = self.object.rule_set.count()
        if self.request.user.has_perms(
            ("santa.view_configuration",
             "santa.view_enrollment",
             "santa.view_rule",
             "santa.view_ruleset")
        ):
            ctx["show_events_link"] = frontend_store.object_events
            store_links = []
            for store in stores.iter_events_url_store_for_user("object", self.request.user):
                url = "{}?{}".format(
                    reverse("santa:configuration_events_store_redirect", args=(self.object.pk,)),
                    urlencode({"es": store.name,
                               "tr": ConfigurationEventsView.default_time_range})
                )
                store_links.append((url, store.name))
            ctx["store_links"] = store_links
        return ctx


class EventsMixin:
    store_method_scope = "object"

    def get_object(self, **kwargs):
        return get_object_or_404(Configuration, pk=kwargs["pk"])

    def get_fetch_kwargs_extra(self):
        return {"key": "santa_configuration", "val": encode_args((self.object.pk,))}

    def get_fetch_url(self):
        return reverse("santa:fetch_configuration_events", args=(self.object.pk,))

    def get_redirect_url(self):
        return reverse("santa:configuration_events", args=(self.object.pk,))

    def get_store_redirect_url(self):
        return reverse("santa:configuration_events_store_redirect", args=(self.object.pk,))

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["configuration"] = self.object
        return ctx


class ConfigurationEventsView(EventsMixin, EventsView):
    permission_required = ("santa.view_configuration",
                           "santa.view_enrollment",
                           "santa.view_rule",
                           "santa.view_ruleset")
    template_name = "santa/configuration_events.html"


class FetchConfigurationEventsView(EventsMixin, FetchEventsView):
    permission_required = ("santa.view_configuration",
                           "santa.view_enrollment",
                           "santa.view_rule",
                           "santa.view_ruleset")


class ConfigurationEventsStoreRedirectView(EventsMixin, EventsStoreRedirectView):
    permission_required = ("santa.view_configuration",
                           "santa.view_enrollment",
                           "santa.view_rule",
                           "santa.view_ruleset")


class UpdateConfigurationView(PermissionRequiredMixin, UpdateView):
    permission_required = "santa.change_configuration"
    model = Configuration
    form_class = ConfigurationForm

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        return ctx


class CreateEnrollmentView(PermissionRequiredMixin, TemplateView):
    permission_required = "santa.add_enrollment"
    template_name = "santa/enrollment_form.html"

    def dispatch(self, request, *args, **kwargs):
        self.configuration = get_object_or_404(Configuration, pk=kwargs["pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_forms(self):
        secret_form_kwargs = {"prefix": "secret"}
        enrollment_form_kwargs = {"configuration": self.configuration,
                                  "initial": {"configuration": self.configuration}}
        if self.request.method == "POST":
            secret_form_kwargs["data"] = self.request.POST
            enrollment_form_kwargs["data"] = self.request.POST
        return (EnrollmentSecretForm(**secret_form_kwargs),
                EnrollmentForm(**enrollment_form_kwargs))

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["configuration"] = self.configuration
        if "secret_form" not in kwargs or "enrollment_form" not in kwargs:
            ctx["secret_form"], ctx["enrollment_form"] = self.get_forms()
        return ctx

    def forms_invalid(self, secret_form, enrollment_form):
        return self.render_to_response(self.get_context_data(secret_form=secret_form,
                                                             enrollment_form=enrollment_form))

    def forms_valid(self, secret_form, enrollment_form):
        secret = secret_form.save()
        secret_form.save_m2m()
        enrollment = enrollment_form.save(commit=False)
        enrollment.secret = secret
        if self.configuration:
            enrollment.configuration = self.configuration
        enrollment.save()
        return HttpResponseRedirect(enrollment.get_absolute_url())

    def post(self, request, *args, **kwargs):
        secret_form, enrollment_form = self.get_forms()
        if secret_form.is_valid() and enrollment_form.is_valid():
            return self.forms_valid(secret_form, enrollment_form)
        else:
            return self.forms_invalid(secret_form, enrollment_form)


class EnrollmentConfigurationView(PermissionRequiredMixin, View):
    permission_required = "santa.view_enrollment"
    response_type = None

    def get(self, request, *args, **kwargs):
        enrollment = get_object_or_404(Enrollment, pk=kwargs["pk"], configuration__pk=kwargs["configuration_pk"])
        if self.response_type == "plist":
            filename, content = build_configuration_plist(enrollment)
            content_type = "application/x-plist"
        elif self.response_type == "configuration_profile":
            filename, content = build_configuration_profile(enrollment)
            content_type = "application/octet-stream"
        else:
            raise ValueError("Unknown enrollment configuration response type: {}".format(self.response_type))
        response = HttpResponse(content, content_type)
        response["Content-Disposition"] = 'attachment; filename="{}"'.format(filename)
        return response


# rules


class ConfigurationRulesView(PermissionRequiredMixin, ListView):
    permission_required = "santa.view_rule"
    paginate_by = 10
    template_name = "santa/configuration_rules.html"

    def dispatch(self, request, *args, **kwargs):
        self.configuration = get_object_or_404(Configuration, pk=kwargs["configuration_pk"])
        self.form = RuleSearchForm(self.request.GET, configuration=self.configuration)
        self.form.is_valid()
        return super().dispatch(request, *args, **kwargs)

    def get_queryset(self):
        return self.form.get_queryset()

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["configuration"] = self.configuration
        ctx["form"] = self.form
        page = ctx["page_obj"]
        if page.has_next():
            qd = self.request.GET.copy()
            qd['page'] = page.next_page_number()
            ctx['next_url'] = "?{}".format(qd.urlencode())
        if page.has_previous():
            qd = self.request.GET.copy()
            qd['page'] = page.previous_page_number()
            ctx['previous_url'] = "?{}".format(qd.urlencode())
        if page.number > 1:
            qd = self.request.GET.copy()
            qd.pop('page', None)
            ctx['reset_link'] = "?{}".format(qd.urlencode())
        return ctx


class CreateConfigurationRuleView(PermissionRequiredMixin, FormView):
    permission_required = "santa.add_rule"
    form_class = RuleForm
    template_name = "santa/rule_form.html"

    def dispatch(self, request, *args, **kwargs):
        self.configuration = get_object_or_404(Configuration, pk=kwargs["configuration_pk"])
        self.binary = self.bundle = self.certificate = self.team_id = None
        try:
            self.binary = File.objects.get(pk=self.request.GET["bin"])
        except (KeyError, File.DoesNotExist):
            pass
        try:
            self.bundle = Bundle.objects.select_related("target").get(pk=self.request.GET["bun"])
        except (KeyError, Bundle.DoesNotExist):
            pass
        try:
            self.certificate = Certificate.objects.get(pk=self.request.GET["cert"])
        except (KeyError, Certificate.DoesNotExist):
            pass
        try:
            self.team_id = self.request.GET["tea"]
        except KeyError:
            pass
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["configuration"] = self.configuration
        kwargs["binary"] = self.binary
        kwargs["bundle"] = self.bundle
        kwargs["certificate"] = self.certificate
        kwargs["team_id"] = self.team_id
        return kwargs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['setup'] = True
        ctx['configuration'] = self.configuration
        if self.binary:
            ctx['files'] = [self.binary]
            ctx['target_type_display'] = "Binary"
            ctx['target_identifier'] = self.binary.sha_256
        else:
            ctx["files"] = []
        if self.bundle:
            ctx['bundle'] = self.bundle
            ctx['target_type_display'] = "Bundle"
            ctx['target_identifier'] = self.bundle.target.identifier
        if self.certificate:
            ctx['certificates'] = [self.certificate]
            ctx['target_type_display'] = "Certificate"
            ctx['target_identifier'] = self.certificate.sha_256
        else:
            ctx["certificates"] = []
        if self.team_id:
            ctx['team_ids'] = Target.objects.get_teamid_objects(self.team_id)
            ctx['target_type_display'] = "Team ID"
            ctx['target_identifier'] = self.team_id
        else:
            ctx['team_ids'] = []
        if self.binary:
            ctx["title"] = "Add Santa binary rule"
        elif self.bundle:
            ctx["title"] = "Add Santa bundle rule"
        elif self.certificate:
            ctx["title"] = "Add Santa certificate rule"
        elif self.team_id:
            ctx["title"] = "Add Santa team ID rule"
        else:
            ctx["title"] = "Add Santa rule"
        return ctx

    def form_valid(self, form):
        rule = form.save()
        rule_update_data = {"rule": rule.serialize_for_event(), "result": "created"}
        transaction.on_commit(lambda: post_santa_rule_update_event(self.request, rule_update_data))
        return redirect(rule)


class UpdateConfigurationRuleView(PermissionRequiredMixin, UpdateView):
    permission_required = "santa.change_rule"
    form_class = UpdateRuleForm

    def get_object(self):
        return get_object_or_404(
            Rule.objects.select_related("configuration", "target"),
            pk=self.kwargs["pk"],
            configuration__pk=self.kwargs["configuration_pk"],
            ruleset__isnull=True
        )

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['setup'] = True
        ctx["configuration"] = ctx["object"].configuration
        ctx["target"] = ctx["object"].target
        ctx["target_type_display"] = ctx["target"].get_type_display()
        ctx["target_identifier"] = ctx["target"].identifier
        ctx["files"] = ctx["target"].files
        ctx["certificates"] = ctx["target"].certificates
        ctx["team_ids"] = ctx["target"].team_ids
        ctx['title'] = "Update santa rule"
        return ctx

    def form_valid(self, form):
        rule = form.save(self.request)
        return redirect(rule)


class DeleteConfigurationRuleView(PermissionRequiredMixin, DeleteView):
    permission_required = "santa.delete_rule"

    def get_object(self):
        return get_object_or_404(
            Rule.objects.select_related("configuration", "target"),
            pk=self.kwargs["pk"],
            configuration__pk=self.kwargs["configuration_pk"],
            ruleset__isnull=True
        )

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['setup'] = True
        ctx['configuration'] = ctx["object"].configuration
        ctx['target'] = ctx["object"].target
        ctx['title'] = "Delete rule"
        return ctx

    def get_success_url(self):
        # see DeletionMixin
        # called before self.object.delete()
        # and after self.get_object()
        rule_update_data = {"rule": self.object.serialize_for_event(), "result": "deleted"}
        transaction.on_commit(lambda: post_santa_rule_update_event(self.request, rule_update_data))
        return reverse("santa:configuration_rules", args=(self.kwargs["configuration_pk"],))


class PickRuleBinaryView(PermissionRequiredMixin, TemplateView):
    permission_required = "santa.add_rule"
    template_name = "santa/pick_rule_binary.html"

    def dispatch(self, request, *args, **kwargs):
        self.configuration = get_object_or_404(Configuration, pk=kwargs["configuration_pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["configuration"] = self.configuration
        form = BinarySearchForm(self.request.GET)
        form.is_valid()
        binaries = list(File.objects.search(**form.cleaned_data))
        existing_rules = {
            rule.target.identifier: rule
            for rule in Rule.objects.select_related("target")
                                    .filter(configuration=self.configuration,
                                            target__type=Target.BINARY,
                                            target__identifier__in=[binary.sha_256 for binary in binaries])
        }
        ctx['binaries'] = [(binary, existing_rules.get(binary.sha_256)) for binary in binaries]
        ctx['form'] = form
        return ctx


class PickRuleBundleView(PermissionRequiredMixin, TemplateView):
    permission_required = "santa.add_rule"
    template_name = "santa/pick_rule_bundle.html"

    def dispatch(self, request, *args, **kwargs):
        self.configuration = get_object_or_404(Configuration, pk=kwargs["configuration_pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["configuration"] = self.configuration
        form = BundleSearchForm(self.request.GET)
        form.is_valid()
        bundles = list(Bundle.objects.search(**form.cleaned_data))
        existing_rules = {
            rule.target.identifier: rule
            for rule in Rule.objects.select_related("target")
                                    .filter(configuration=self.configuration,
                                            target__type=Target.BUNDLE,
                                            target__identifier__in=[bundle.target.identifier for bundle in bundles])
        }
        ctx['bundles'] = [(bundle, existing_rules.get(bundle.target.identifier)) for bundle in bundles]
        ctx['form'] = form
        return ctx


class PickRuleCertificateView(PermissionRequiredMixin, TemplateView):
    permission_required = "santa.add_rule"
    template_name = "santa/pick_rule_certificate.html"

    def dispatch(self, request, *args, **kwargs):
        self.configuration = get_object_or_404(Configuration, pk=kwargs["configuration_pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["configuration"] = self.configuration
        form = CertificateSearchForm(self.request.GET)
        form.is_valid()
        certificates = list(File.objects.search_certificates(**form.cleaned_data))
        existing_rules = {
            rule.target.identifier: rule
            for rule in Rule.objects.select_related("target")
                                    .filter(configuration=self.configuration,
                                            target__type=Target.CERTIFICATE,
                                            target__identifier__in=[certificate.sha_256
                                                                    for certificate in certificates])
        }
        ctx['certificates'] = [(certificate, existing_rules.get(certificate.sha_256)) for certificate in certificates]
        ctx['form'] = form
        return ctx


class PickRuleTeamIDView(PermissionRequiredMixin, TemplateView):
    permission_required = "santa.add_rule"
    template_name = "santa/pick_rule_team_id.html"

    def dispatch(self, request, *args, **kwargs):
        self.configuration = get_object_or_404(Configuration, pk=kwargs["configuration_pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["configuration"] = self.configuration
        form = TeamIDSearchForm(self.request.GET)
        form.is_valid()
        team_ids = Target.objects.search_teamid_objects(**form.cleaned_data)
        existing_rules = {
            rule.target.identifier: rule
            for rule in Rule.objects.select_related("target")
                                    .filter(configuration=self.configuration,
                                            target__type=Target.TEAM_ID,
                                            target__identifier__in=[team_id.organizational_unit
                                                                    for team_id in team_ids])
        }
        ctx['team_ids'] = [(team_id, existing_rules.get(team_id.organizational_unit)) for team_id in team_ids]
        ctx['form'] = form
        return ctx
