import logging
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.shortcuts import get_object_or_404, redirect
from django.views.generic import DeleteView, TemplateView
from zentral.contrib.inventory.forms import EnrollmentSecretForm
from zentral.contrib.osquery.forms import EnrollmentForm
from zentral.contrib.osquery.models import Configuration, Enrollment


logger = logging.getLogger('zentral.contrib.osquery.views.enrollments')


class CreateEnrollmentView(PermissionRequiredMixin, TemplateView):
    permission_required = "osquery.add_enrollment"
    template_name = "osquery/enrollment_form.html"

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
        if self.configuration:
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
    permission_required = "osquery.delete_enrollment"

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
    permission_required = "osquery.change_enrollment"
    template_name = "osquery/enrollment_confirm_version_bump.html"

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
