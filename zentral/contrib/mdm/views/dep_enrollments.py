import logging
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.shortcuts import get_object_or_404, redirect
from django.views.generic import DetailView, TemplateView
from zentral.contrib.inventory.forms import EnrollmentSecretForm
from zentral.contrib.mdm.dep import add_dep_profile
from zentral.contrib.mdm.dep_client import DEPClient, DEPClientError
from zentral.contrib.mdm.forms import CreateDEPEnrollmentForm, DEPEnrollmentCustomViewForm, UpdateDEPEnrollmentForm
from zentral.contrib.mdm.models import DEPEnrollment, DEPEnrollmentCustomView
from zentral.contrib.mdm.skip_keys import skippable_setup_panes
from zentral.utils.views import CreateViewWithAudit, DeleteViewWithAudit, UpdateViewWithAudit


logger = logging.getLogger("zentral.contrib.mdm.views.dep_enrollments")


# enrollments


class CreateDEPEnrollmentView(PermissionRequiredMixin, TemplateView):
    permission_required = "mdm.add_depenrollment"
    template_name = "mdm/depenrollment_form.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        dep_enrollment_form = kwargs.get("dep_enrollment_form")
        if not dep_enrollment_form:
            dep_enrollment_form = CreateDEPEnrollmentForm(prefix="de")
        context["dep_enrollment_form"] = dep_enrollment_form
        enrollment_secret_form = kwargs.get("enrollment_secret_form")
        if not enrollment_secret_form:
            enrollment_secret_form = EnrollmentSecretForm(
                prefix="es",
                no_restrictions=True,
            )
        context["enrollment_secret_form"] = enrollment_secret_form
        return context

    def post(self, request, *args, **kwargs):
        dep_enrollment_form = CreateDEPEnrollmentForm(request.POST, prefix="de")
        enrollment_secret_form = EnrollmentSecretForm(
            request.POST,
            prefix="es",
            no_restrictions=True,
        )
        if dep_enrollment_form.is_valid() and enrollment_secret_form.is_valid():
            dep_enrollment = dep_enrollment_form.save(commit=False)
            dep_enrollment.enrollment_secret = enrollment_secret_form.save()
            enrollment_secret_form.save_m2m()
            try:
                add_dep_profile(dep_enrollment)
            except DEPClientError as error:
                dep_enrollment_form.add_error(None, str(error))
            else:
                return redirect(dep_enrollment)
        return self.render_to_response(
            self.get_context_data(
                dep_enrollment_form=dep_enrollment_form,
                enrollment_secret_form=enrollment_secret_form,
            )
        )


class DEPEnrollmentView(PermissionRequiredMixin, DetailView):
    permission_required = "mdm.view_depenrollment"
    model = DEPEnrollment

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["skip_keys"] = []
        for skey, content in skippable_setup_panes:
            for okey in self.object.skip_setup_items:
                if okey == skey:
                    ctx["skip_keys"].append(content)

        ctx["custom_views"] = list(
            ctx["object"]
            .depenrollmentcustomview_set.select_related("custom_view")
            .order_by("custom_view__requires_authentication", "weight")
        )
        ctx["custom_views_count"] = len(ctx["custom_views"])
        ctx["assigned_devices_count"] = ctx["object"].assigned_devices().count()
        ctx["enrollment_sessions_count"] = ctx[
            "object"
        ].depenrollmentsession_set.count()
        return ctx


class CheckDEPEnrollmentView(PermissionRequiredMixin, DetailView):
    permission_required = "mdm.view_depenrollment"
    model = DEPEnrollment
    template_name = "mdm/depenrollment_check.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        dep_client = DEPClient.from_dep_virtual_server(self.object.virtual_server)
        ctx["fetched_profile"] = dep_client.get_profile(self.object.uuid)
        return ctx


class UpdateDEPEnrollmentView(PermissionRequiredMixin, TemplateView):
    permission_required = "mdm.change_depenrollment"
    template_name = "mdm/depenrollment_form.html"

    def dispatch(self, request, *args, **kwargs):
        self.object = get_object_or_404(DEPEnrollment, pk=kwargs["pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["object"] = self.object
        dep_enrollment_form = kwargs.get("dep_enrollment_form")
        if not dep_enrollment_form:
            dep_enrollment_form = UpdateDEPEnrollmentForm(
                prefix="de", instance=self.object
            )
        context["dep_enrollment_form"] = dep_enrollment_form
        enrollment_secret_form = kwargs.get("enrollment_secret_form")
        if not enrollment_secret_form:
            enrollment_secret_form = EnrollmentSecretForm(
                prefix="es",
                instance=self.object.enrollment_secret,
                no_restrictions=True,
            )
        context["enrollment_secret_form"] = enrollment_secret_form
        return context

    def post(self, request, *args, **kwargs):
        dep_enrollment_form = UpdateDEPEnrollmentForm(
            request.POST, prefix="de", instance=self.object
        )
        enrollment_secret_form = EnrollmentSecretForm(
            request.POST,
            prefix="es",
            instance=self.object.enrollment_secret,
            no_restrictions=True,
        )
        if dep_enrollment_form.is_valid() and enrollment_secret_form.is_valid():
            dep_enrollment = dep_enrollment_form.save(commit=False)
            dep_enrollment.enrollment_secret = enrollment_secret_form.save()
            enrollment_secret_form.save_m2m()
            try:
                add_dep_profile(dep_enrollment)
            except DEPClientError as error:
                dep_enrollment_form.add_error(None, str(error))
            else:
                return redirect(dep_enrollment)
        return self.render_to_response(
            self.get_context_data(
                dep_enrollment_form=dep_enrollment_form,
                enrollment_secret_form=enrollment_secret_form,
            )
        )


# custom views


class DEPEnrollmentCustomViewMixin:
    def dispatch(self, request, *args, **kwargs):
        self.dep_enrollment = get_object_or_404(DEPEnrollment, pk=kwargs["enrollment_pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["dep_enrollment"] = self.dep_enrollment
        return ctx


class CreateDEPEnrollmentCustomViewView(PermissionRequiredMixin, DEPEnrollmentCustomViewMixin, CreateViewWithAudit):
    permission_required = "mdm.add_depenrollmentcustomview"
    model = DEPEnrollmentCustomView
    form_class = DEPEnrollmentCustomViewForm

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["dep_enrollment"] = self.dep_enrollment
        return kwargs


class UpdateDEPEnrollmentCustomViewView(PermissionRequiredMixin, DEPEnrollmentCustomViewMixin, UpdateViewWithAudit):
    permission_required = "mdm.change_depenrollmentcustomview"
    model = DEPEnrollmentCustomView
    form_class = DEPEnrollmentCustomViewForm

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["dep_enrollment"] = self.dep_enrollment
        return kwargs


class DeleteDEPEnrollmentCustomViewView(PermissionRequiredMixin, DEPEnrollmentCustomViewMixin, DeleteViewWithAudit):
    permission_required = "mdm.delete_depenrollmentcustomview"
    model = DEPEnrollmentCustomView

    def get_success_url(self):
        return self.dep_enrollment.get_absolute_url()
