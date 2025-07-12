import logging
from urllib.parse import urlencode
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.db.models import F, Count
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse, reverse_lazy
from django.views.generic import DeleteView, DetailView, ListView, TemplateView, View
from zentral.contrib.inventory.forms import EnrollmentSecretForm
from zentral.contrib.inventory.models import MetaMachine
from zentral.core.compliance_checks.forms import ComplianceCheckForm
from zentral.core.events.base import AuditEvent
from zentral.core.stores.conf import stores
from zentral.core.stores.views import EventsView, FetchEventsView, EventsStoreRedirectView
from zentral.utils.terraform import build_config_response
from zentral.utils.text import encode_args
from zentral.utils.views import CreateViewWithAudit, DeleteViewWithAudit, UpdateViewWithAudit, UserPaginationListView
from .compliance_checks import MunkiScriptCheck
from .forms import ConfigurationForm, EnrollmentForm, ScriptCheckForm, ScriptCheckSearchForm
from .models import Configuration, Enrollment, MunkiState, PrincipalUserDetectionSource, ScriptCheck
from .terraform import iter_resources


logger = logging.getLogger('zentral.contrib.munki.views')


# index


class IndexView(LoginRequiredMixin, TemplateView):
    template_name = "munki/index.html"

    def get_context_data(self, **kwargs):
        if not self.request.user.has_module_perms("munki"):
            raise PermissionDenied("Not allowed")
        return super().get_context_data(**kwargs)


# Terraform export


class TerraformExportView(PermissionRequiredMixin, View):
    permission_required = (
        "munki.view_configuration",
        "munki.view_enrollment",
        "munki.view_scriptcheck",
    )

    def get(self, request, *args, **kwargs):
        return build_config_response(iter_resources(), "terraform_munki")


# configuration


class ConfigurationListView(PermissionRequiredMixin, ListView):
    permission_required = "munki.view_configuration"
    model = Configuration

    def get_queryset(self):
        return super().get_queryset().annotate(Count("enrollment", distinct=True),
                                               Count("enrollment__enrolledmachine"))

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["configuration_count"] = ctx["object_list"].count()
        return ctx


class CreateConfigurationView(PermissionRequiredMixin, CreateViewWithAudit):
    permission_required = "munki.add_configuration"
    model = Configuration
    form_class = ConfigurationForm


class ConfigurationView(PermissionRequiredMixin, DetailView):
    permission_required = "munki.view_configuration"
    model = Configuration

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        # principal user detection sources
        ctx["principal_user_detection_sources"] = ", ".join(
            sorted(PrincipalUserDetectionSource[src].value for src in self.object.principal_user_detection_sources)
        )
        # enrollments
        enrollments = []
        enrollment_count = 0
        for enrollment in self.object.enrollment_set.select_related("secret").all().order_by("pk"):
            enrollment_count += 1
            distributor = None
            distributor_link = False
            dct = enrollment.distributor_content_type
            if dct:
                distributor = enrollment.distributor
                if self.request.user.has_perm(f"{dct.app_label}.view_{dct.model}"):
                    distributor_link = True
            enrollments.append((enrollment, distributor, distributor_link))
        ctx["enrollments"] = enrollments
        ctx["enrollment_count"] = enrollment_count

        # events
        if self.request.user.has_perms(ConfigurationEventsView.permission_required):
            ctx["show_events_link"] = stores.admin_console_store.object_events
        return ctx


class UpdateConfigurationView(PermissionRequiredMixin, UpdateViewWithAudit):
    permission_required = "munki.change_configuration"
    model = Configuration
    form_class = ConfigurationForm


# events

class EventsMixin:
    store_method_scope = "object"

    def get_object(self, **kwargs):
        return get_object_or_404(Configuration, pk=kwargs["pk"])

    def get_fetch_kwargs_extra(self):
        return {"key": "munki_configuration", "val": encode_args((self.object.pk,))}

    def get_fetch_url(self):
        return reverse("munki:fetch_configuration_events", args=(self.object.pk,))

    def get_redirect_url(self):
        return reverse("munki:configuration_events", args=(self.object.pk,))

    def get_store_redirect_url(self):
        return reverse("munki:configuration_events_store_redirect", args=(self.object.pk,))

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["configuration"] = self.object
        return ctx


class ConfigurationEventsView(EventsMixin, EventsView):
    permission_required = ("munki.view_configuration",
                           "munki.view_enrollment")
    template_name = "munki/configuration_events.html"


class FetchConfigurationEventsView(EventsMixin, FetchEventsView):
    permission_required = ("munki.view_configuration",
                           "munki.view_enrollment")


class ConfigurationEventsStoreRedirectView(EventsMixin, EventsStoreRedirectView):
    permission_required = ("munki.view_configuration",
                           "munki.view_enrollment")


# enrollment


class CreateEnrollmentView(PermissionRequiredMixin, TemplateView):
    permission_required = "munki.add_enrollment"
    template_name = "munki/enrollment_form.html"

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
        enrollment.configuration = self.configuration
        enrollment.save()
        return redirect(enrollment)

    def post(self, request, *args, **kwargs):
        secret_form, enrollment_form = self.get_forms()
        if secret_form.is_valid() and enrollment_form.is_valid():
            return self.forms_valid(secret_form, enrollment_form)
        else:
            return self.forms_invalid(secret_form, enrollment_form)


class DeleteEnrollmentView(PermissionRequiredMixin, DeleteView):
    permission_required = "munki.delete_enrollment"

    def get_queryset(self):
        return (Enrollment.objects.select_related("configuration")
                                  .filter(configuration__pk=self.kwargs["configuration_pk"],
                                          distributor_content_type__isnull=True,
                                          distributor_pk__isnull=True))

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["configuration"] = self.object.configuration
        ctx["enrolled_machine_count"] = self.object.enrolledmachine_set.count()
        return ctx

    def get_success_url(self):
        return self.object.configuration.get_absolute_url()


class EnrollmentBumpVersionView(PermissionRequiredMixin, TemplateView):
    permission_required = "munki.change_enrollment"
    template_name = "munki/enrollment_confirm_version_bump.html"

    def dispatch(self, request, *args, **kwargs):
        self.enrollment = get_object_or_404(
            Enrollment,
            pk=kwargs["pk"],
            configuration__pk=kwargs["configuration_pk"],
            distributor_content_type__isnull=True,
            distributor_pk__isnull=True,
        )
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["enrollment"] = self.enrollment
        return ctx

    def post(self, request, *args, **kwargs):
        self.enrollment.save()  # will bump the version
        return redirect(self.enrollment)


# script check


class ScriptCheckListView(PermissionRequiredMixin, UserPaginationListView):
    permission_required = "munki.view_scriptcheck"
    template_name = "munki/scriptcheck_list.html"

    def dispatch(self, request, *args, **kwargs):
        self.form = ScriptCheckSearchForm(self.request.GET)
        self.form.is_valid()
        return super().dispatch(request, *args, **kwargs)

    def get_queryset(self):
        return self.form.get_queryset()

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["form"] = self.form
        page = ctx["page_obj"]
        bc = []
        if page.number > 1:
            qd = self.request.GET.copy()
            qd.pop('page', None)
            ctx['reset_link'] = "?{}".format(qd.urlencode())
            reset_link = "?{}".format(qd.urlencode())
        else:
            reset_link = None
        if self.form.has_changed():
            bc.append((reverse("munki:script_checks"), "Script checks"))
            bc.append((reset_link, "Search"))
        else:
            bc.append((reset_link, "Script checks"))
        bc.append((None, f"page {page.number} of {page.paginator.num_pages}"))
        ctx["breadcrumbs"] = bc
        return ctx


class CreateScriptCheckView(PermissionRequiredMixin, TemplateView):
    permission_required = "munki.add_scriptcheck"
    template_name = "munki/scriptcheck_form.html"

    def get_forms(self):
        compliance_check_form_kwargs = {
            "prefix": "ccf",
            "model": MunkiScriptCheck.get_model()
        }
        script_check_form_kwargs = {
            "prefix": "scf"
        }
        if self.request.method == "POST":
            compliance_check_form_kwargs["data"] = self.request.POST
            script_check_form_kwargs["data"] = self.request.POST
        return (
            ComplianceCheckForm(**compliance_check_form_kwargs),
            ScriptCheckForm(**script_check_form_kwargs)
        )

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        if "compliance_check_form" not in kwargs and "script_check_form" not in kwargs:
            ctx["compliance_check_form"], ctx["script_check_form"] = self.get_forms()
        return ctx

    def forms_invalid(self, compliance_check_form, script_check_form):
        return self.render_to_response(
            self.get_context_data(compliance_check_form=compliance_check_form,
                                  script_check_form=script_check_form)
        )

    def forms_valid(self, compliance_check_form, script_check_form):
        compliance_check = compliance_check_form.save(commit=False)
        compliance_check.model = MunkiScriptCheck.get_model()
        compliance_check.save()
        script_check = script_check_form.save(commit=False)
        script_check.compliance_check = compliance_check
        script_check.save()
        script_check_form.save_m2m()

        def post_event():
            event = AuditEvent.build_from_request_and_instance(
                self.request, script_check,
                action=AuditEvent.Action.CREATED,
            )
            event.post()
        transaction.on_commit(lambda: post_event())
        return redirect(script_check)

    def post(self, request, *args, **kwargs):
        compliance_check_form, script_check_form = self.get_forms()
        if compliance_check_form.is_valid() and script_check_form.is_valid():
            return self.forms_valid(compliance_check_form, script_check_form)
        else:
            return self.forms_invalid(compliance_check_form, script_check_form)


class ScriptCheckView(PermissionRequiredMixin, DetailView):
    permission_required = "munki.view_scriptcheck"
    model = ScriptCheck

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data()
        ctx["compliance_check"] = self.object.compliance_check
        if self.request.user.has_perm(ScriptCheckEventsMixin.permission_required):
            ctx["show_events_link"] = stores.admin_console_store.object_events
            store_links = []
            for store in stores.iter_events_url_store_for_user("object", self.request.user):
                url = "{}?{}".format(
                    reverse("munki:script_check_events_store_redirect", args=(self.object.pk,)),
                    urlencode({"es": store.name,
                               "tr": ScriptCheckEventsView.default_time_range})
                )
                store_links.append((url, store.name))
            ctx["store_links"] = store_links
        return ctx


class UpdateScriptCheckView(PermissionRequiredMixin, TemplateView):
    permission_required = "munki.change_scriptcheck"
    template_name = "munki/scriptcheck_form.html"

    def get_object(self, kwargs=None):
        if kwargs is None:
            kwargs = self.kwargs
        return get_object_or_404(
            ScriptCheck.objects.select_related("compliance_check").all(),
            pk=kwargs["pk"]
        )

    def dispatch(self, request, *args, **kwargs):
        self.object = self.get_object(kwargs)
        self.compliance_check = self.object.compliance_check
        return super().dispatch(request, *args, **kwargs)

    def get_forms(self):
        compliance_check_form_kwargs = {
            "prefix": "ccf",
            "instance": self.compliance_check,
            "model": MunkiScriptCheck.get_model()
        }
        script_check_form_kwargs = {
            "prefix": "scf",
            "instance": self.object,
        }
        if self.request.method == "POST":
            compliance_check_form_kwargs["data"] = self.request.POST
            script_check_form_kwargs["data"] = self.request.POST
        return (
            ComplianceCheckForm(**compliance_check_form_kwargs),
            ScriptCheckForm(**script_check_form_kwargs)
        )

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        if "compliance_check_form" not in kwargs and "script_check_form" not in kwargs:
            ctx["compliance_check_form"], ctx["script_check_form"] = self.get_forms()
        ctx["object"] = self.object
        ctx["compliance_check"] = self.compliance_check
        return ctx

    def forms_invalid(self, compliance_check_form, script_check_form):
        return self.render_to_response(
            self.get_context_data(compliance_check_form=compliance_check_form,
                                  script_check_form=script_check_form)
        )

    def forms_valid(self, compliance_check_form, script_check_form):
        prev_value = self.get_object().serialize_for_event()  # self.object is already updated
        compliance_check = compliance_check_form.save(commit=False)
        compliance_check.model = MunkiScriptCheck.get_model()
        if script_check_form.has_changed():
            compliance_check.version = F("version") + 1
        compliance_check.save()
        script_check = script_check_form.save(commit=False)
        script_check.compliance_check = compliance_check
        script_check.save()
        script_check_form.save_m2m()
        if compliance_check_form.has_changed() or script_check_form.has_changed():
            script_check.refresh_from_db()  # get version number

            def post_event():
                event = AuditEvent.build_from_request_and_instance(
                    self.request, script_check,
                    action=AuditEvent.Action.UPDATED,
                    prev_value=prev_value
                )
                event.post()

            transaction.on_commit(lambda: post_event())
        return redirect(script_check)

    def post(self, request, *args, **kwargs):
        compliance_check_form, script_check_form = self.get_forms()
        if compliance_check_form.is_valid() and script_check_form.is_valid():
            return self.forms_valid(compliance_check_form, script_check_form)
        else:
            return self.forms_invalid(compliance_check_form, script_check_form)


class DeleteScriptCheckView(PermissionRequiredMixin, DeleteViewWithAudit):
    permission_required = "munki.delete_scriptcheck"
    model = ScriptCheck
    success_url = reverse_lazy("munki:script_checks")


class ScriptCheckEventsMixin:
    permission_required = "munki.view_scriptcheck"
    store_method_scope = "object"

    def get_object(self, **kwargs):
        return get_object_or_404(
            ScriptCheck.objects.select_related("compliance_check").all(),
            pk=kwargs["pk"]
        )

    def get_fetch_kwargs_extra(self):
        return {"key": "munki_script_check", "val": encode_args((self.object.pk,))}

    def get_fetch_url(self):
        return reverse("munki:fetch_script_check_events", args=(self.object.pk,))

    def get_redirect_url(self):
        return reverse("munki:script_check_events", args=(self.object.pk,))

    def get_store_redirect_url(self):
        return reverse("munki:script_check_events_store_redirect", args=(self.object.pk,))

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["script_check"] = self.object
        ctx["compliance_check"] = self.object.compliance_check
        return ctx


class ScriptCheckEventsView(ScriptCheckEventsMixin, EventsView):
    template_name = "munki/scriptcheck_events.html"


class FetchScriptCheckEventsView(ScriptCheckEventsMixin, FetchEventsView):
    pass


class ScriptCheckEventsStoreRedirectView(ScriptCheckEventsMixin, EventsStoreRedirectView):
    pass


# Machine actions


class ForceMachineFullSync(PermissionRequiredMixin, TemplateView):
    permission_required = "munki.change_munkistate"
    template_name = "munki/force_machine_full_sync_confirm.html"

    def get_munki_state(self):
        self.machine = MetaMachine.from_urlsafe_serial_number(self.kwargs["urlsafe_serial_number"])
        self.munki_state = get_object_or_404(MunkiState, machine_serial_number=self.machine.serial_number)

    def get_context_data(self, **kwargs):
        self.get_munki_state()
        ctx = super().get_context_data(**kwargs)
        ctx["machine"] = self.machine
        return ctx

    def post(self, request, *args, **kwargs):
        self.get_munki_state()
        self.munki_state.force_full_sync()
        messages.info(request, f"Full sync forced during next Munki run for machine {self.machine.serial_number}")
        return redirect(self.machine.get_absolute_url())
