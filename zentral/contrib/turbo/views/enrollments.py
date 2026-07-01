from django.contrib.auth.mixins import PermissionRequiredMixin
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect
from django.views.generic import TemplateView
from zentral.contrib.inventory.forms import EnrollmentSecretForm
from zentral.core.events.base import AuditEvent
from zentral.utils.views import DeleteViewWithAudit
from ..forms import EnrollmentForm
from ..models import Configuration, Enrollment


class CreateEnrollmentView(PermissionRequiredMixin, TemplateView):
    permission_required = "turbo.add_enrollment"
    template_name = "turbo/enrollment_form.html"

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

        def post_event():
            event = AuditEvent.build_from_request_and_instance(
                self.request, enrollment,
                action=AuditEvent.Action.CREATED,
            )
            event.post()

        transaction.on_commit(post_event)
        return redirect(enrollment)

    def post(self, request, *args, **kwargs):
        secret_form, enrollment_form = self.get_forms()
        if secret_form.is_valid() and enrollment_form.is_valid():
            return self.forms_valid(secret_form, enrollment_form)
        else:
            return self.forms_invalid(secret_form, enrollment_form)


class DeleteEnrollmentView(PermissionRequiredMixin, DeleteViewWithAudit):
    permission_required = "turbo.delete_enrollment"

    def get_queryset(self):
        return (Enrollment.objects.can_be_deleted()
                                  .select_related("configuration")
                                  .filter(configuration__pk=self.kwargs["configuration_pk"]))

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["configuration"] = self.object.configuration
        return ctx

    def get_success_url(self):
        return self.object.configuration.get_absolute_url()


class EnrollmentBumpVersionView(PermissionRequiredMixin, TemplateView):
    permission_required = "turbo.change_enrollment"
    template_name = "turbo/enrollment_confirm_version_bump.html"

    def dispatch(self, request, *args, **kwargs):
        self.enrollment = get_object_or_404(
            Enrollment.objects.can_be_updated(),
            pk=kwargs["pk"],
            configuration__pk=kwargs["configuration_pk"],
        )
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["enrollment"] = self.enrollment
        return ctx

    def post(self, request, *args, **kwargs):
        prev_value = self.enrollment.serialize_for_event()
        self.enrollment.save()  # will bump the version

        def post_event():
            event = AuditEvent.build_from_request_and_instance(
                self.request, self.enrollment,
                action=AuditEvent.Action.UPDATED,
                prev_value=prev_value,
            )
            event.post()

        transaction.on_commit(post_event)
        return redirect(self.enrollment)
