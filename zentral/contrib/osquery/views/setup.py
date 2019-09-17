import logging
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.views.generic import CreateView, DetailView, ListView, TemplateView, UpdateView, View
from zentral.contrib.inventory.forms import EnrollmentSecretForm
from zentral.contrib.osquery.forms import ConfigurationForm, EnrollmentForm
from zentral.contrib.osquery.linux_script.builder import OsqueryZentralEnrollScriptBuilder
from zentral.contrib.osquery.models import Configuration, Enrollment
from zentral.contrib.osquery.osx_package.builder import OsqueryZentralEnrollPkgBuilder
from zentral.contrib.osquery.powershell_script.builder import OsqueryZentralEnrollPowershellScriptBuilder

logger = logging.getLogger('zentral.contrib.osquery.views.setup')


class ConfigurationListView(LoginRequiredMixin, ListView):
    model = Configuration

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["configurations_count"] = ctx["object_list"].count()
        return ctx


class CreateConfigurationView(LoginRequiredMixin, CreateView):
    model = Configuration
    form_class = ConfigurationForm

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        return ctx


class ConfigurationView(LoginRequiredMixin, DetailView):
    model = Configuration

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        enrollments = list(self.object.enrollment_set.select_related("secret").all().order_by("id"))
        ctx["enrollments"] = enrollments
        ctx["enrollments_count"] = len(enrollments)
        return ctx


class UpdateConfigurationView(LoginRequiredMixin, UpdateView):
    model = Configuration
    form_class = ConfigurationForm

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        return ctx


class CreateEnrollmentView(LoginRequiredMixin, TemplateView):
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


class EnrollmentPackageView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        enrollment = get_object_or_404(Enrollment, pk=kwargs["pk"], configuration__pk=kwargs["configuration_pk"])
        builder = OsqueryZentralEnrollPkgBuilder(enrollment)
        return builder.build_and_make_response()


class EnrollmentScriptView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        enrollment = get_object_or_404(Enrollment, pk=kwargs["pk"], configuration__pk=kwargs["configuration_pk"])
        builder = OsqueryZentralEnrollScriptBuilder(enrollment)
        return builder.build_and_make_response()


class EnrollmentPowershellScriptView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        enrollment = get_object_or_404(Enrollment, pk=kwargs["pk"], configuration__pk=kwargs["configuration_pk"])
        builder = OsqueryZentralEnrollPowershellScriptBuilder(enrollment)
        return builder.build_and_make_response()
