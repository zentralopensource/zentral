import logging
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import SuspiciousOperation
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.views.generic import CreateView, DetailView, ListView, TemplateView, UpdateView, View
from zentral.contrib.mdm.cms import sign_payload_openssl
from zentral.contrib.mdm.dep import add_dep_token_certificate, add_dep_profile, assign_dep_device_profile
from zentral.contrib.mdm.dep_client import DEPClient, DEPClientError
from zentral.contrib.mdm.forms import (AssignDEPDeviceProfileForm, DEPProfileForm, EncryptedDEPTokenForm,
                                       OTAEnrollmentForm, OTAEnrollmentSecretForm, PushCertificateForm)
from zentral.contrib.mdm.models import (MetaBusinessUnitPushCertificate, PushCertificate,
                                        DEPDevice, DEPProfile, DEPToken, DEPVirtualServer,
                                        OTAEnrollment)
from zentral.contrib.mdm.payloads import (build_payload_response,
                                          build_root_ca_configuration_profile,
                                          build_profile_service_payload)

logger = logging.getLogger('zentral.contrib.mdm.views.setup')


class RootCAView(View):
    def get(self, request, *args, **kwargs):
        return build_payload_response(sign_payload_openssl(build_root_ca_configuration_profile()), "zentral_root_ca")


class IndexView(LoginRequiredMixin, TemplateView):
    template_name = "mdm/index.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        return ctx


# Push certificates


class PushCertificatesView(LoginRequiredMixin, ListView):
    model = PushCertificate

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        return ctx


class AddPushCertificateView(LoginRequiredMixin, CreateView):
    model = PushCertificate
    form_class = PushCertificateForm

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        return ctx


class PushCertificateView(LoginRequiredMixin, DetailView):
    model = PushCertificate

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["mbu_list"] = list(mbups.meta_business_unit
                               for mbups in (ctx["object"].metabusinessunitpushcertificate_set
                                                          .select_related("meta_business_unit")
                                                          .order_by("meta_business_unit__name")
                                                          .all()))
        return ctx


class AddPushCertificateBusinessUnitView(LoginRequiredMixin, CreateView):
    model = MetaBusinessUnitPushCertificate
    fields = ("meta_business_unit",)

    def dispatch(self, request, *args, **kwargs):
        self.push_certificate = get_object_or_404(PushCertificate, pk=kwargs["pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["push_certificate"] = self.push_certificate
        return ctx

    def form_valid(self, form):
        mbups = form.save(commit=False)
        mbups.push_certificate = self.push_certificate
        mbups.save()
        return HttpResponseRedirect(self.push_certificate.get_absolute_url())


# OTA enrollment


class OTAEnrollmentListView(LoginRequiredMixin, ListView):
    model = OTAEnrollment

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        return ctx


class CreateOTAEnrollmentView(LoginRequiredMixin, TemplateView):
    template_name = "mdm/create_ota_enrollment.html"
    model = OTAEnrollment
    fields = ("meta_business_unit", "tags",
              "serial_numbers", "udids",
              "quota", "expired_at")

    def get_context_data(self, **kwargs):
        ota_enrollment_form = kwargs.get("ota_enrollment_form")
        if not ota_enrollment_form:
            ota_enrollment_form = OTAEnrollmentForm(prefix="oe")
        ota_enrollment_secret_form = kwargs.get("ota_enrollment_secret_form")
        if not ota_enrollment_secret_form:
            ota_enrollment_secret_form = OTAEnrollmentSecretForm(prefix="oes")
        return {"setup": True,
                "ota_enrollment_form": ota_enrollment_form,
                "ota_enrollment_secret_form": ota_enrollment_secret_form}

    def post(self, request, *args, **kwargs):
        ota_enrollment_form = OTAEnrollmentForm(request.POST, prefix="oe")
        ota_enrollment_secret_form = OTAEnrollmentSecretForm(request.POST, prefix="oes")
        if ota_enrollment_form.is_valid() and ota_enrollment_secret_form.is_valid():
            ota_enrollment = ota_enrollment_form.save(commit=False)
            ota_enrollment.enrollment_secret = ota_enrollment_secret_form.save()
            ota_enrollment.save()
            return HttpResponseRedirect(reverse("mdm:ota_enrollment",
                                                args=(ota_enrollment.pk,)))
        else:
            return self.render_to_response(
                self.get_context_data(ota_enrollment_form=ota_enrollment_form,
                                      ota_enrollment_secret_form=ota_enrollment_secret_form)
            )

    def form_valid(self, form):
        ota_enrollment = form.save(commit=False)
        ota_enrollment.save()
        return HttpResponseRedirect(ota_enrollment.get_absolute_url())


class OTAEnrollmentView(LoginRequiredMixin, DetailView):
    template_name = "mdm/ota_enrollment.html"
    model = OTAEnrollment

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        # TODO: pagination
        ctx["ota_enrollment_sessions"] = (ctx["object"].otaenrollmentsession_set.all()
                                                       .select_related("enrollment_secret")
                                                       .order_by("-created_at"))
        ctx["ota_enrollment_sessions_count"] = ctx["ota_enrollment_sessions"].count()
        return ctx


class DownloadProfileServicePayloadView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        ota_enrollment = get_object_or_404(OTAEnrollment, pk=kwargs["pk"])
        if not ota_enrollment.enrollment_secret.is_valid():
            # should not happen
            raise SuspiciousOperation
        return build_payload_response(sign_payload_openssl(build_profile_service_payload(ota_enrollment)),
                                      "zentral_profile_service")


class RevokeOTAEnrollmentView(LoginRequiredMixin, TemplateView):
    template_name = "mdm/revoke_ota_enrollment.html"

    def dispatch(self, request, *args, **kwargs):
        self.ota_enrollment = get_object_or_404(OTAEnrollment, pk=kwargs["pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["ota_enrollment"] = self.ota_enrollment
        return ctx

    def post(self, request, *args, **kwargs):
        self.ota_enrollment.revoke()
        return HttpResponseRedirect(self.ota_enrollment.get_absolute_url())


# DEP Tokens


class DEPTokensView(LoginRequiredMixin, ListView):
    model = DEPToken

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        return ctx


class CreateDEPTokenView(LoginRequiredMixin, CreateView):
    model = DEPToken
    fields = "__all__"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        return ctx

    def form_valid(self, form):
        self.object = form.save()
        add_dep_token_certificate(self.object)
        return super().form_valid(form)


class DEPTokenView(LoginRequiredMixin, DetailView):
    model = DEPToken

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        return ctx


class DownloadDEPTokenCertificateView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        dep_token = get_object_or_404(DEPToken, pk=kwargs["pk"], consumer_key__isnull=True)
        filename = "dep_token_{}.pem".format(dep_token.pk)
        response = HttpResponse(dep_token.certificate, content_type="application/x-pem-file")
        response["Content-Disposition"] = 'attachment; filename="{}"'.format(filename)
        return response


class UploadEncryptedDEPTokenView(LoginRequiredMixin, UpdateView):
    form_class = EncryptedDEPTokenForm
    model = DEPToken
    template_name = "mdm/deptoken_upload_encrypted_token.html"

    def form_valid(self, form):
        dep_token = form.save()
        return HttpResponseRedirect(reverse("mdm:dep_virtual_server", args=(dep_token.virtual_server.pk,)))


# DEP virtual servers


class DEPVirtualServersView(LoginRequiredMixin, ListView):
    model = DEPVirtualServer


class DEPVirtualServerView(LoginRequiredMixin, DetailView):
    model = DEPVirtualServer


# DEP profiles


class DEPProfilesView(LoginRequiredMixin, ListView):
    model = DEPProfile


class CreateDEPProfileView(LoginRequiredMixin, CreateView):
    model = DEPProfile
    form_class = DEPProfileForm
    pk_url_kwarg = "profile_pk"

    def dispatch(self, request, *args, **kwargs):
        self.dep_virtual_server = get_object_or_404(DEPVirtualServer, pk=kwargs["pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["dep_virtual_server"] = self.dep_virtual_server
        return ctx

    def form_valid(self, form):
        dep_profile = form.save(commit=False)
        dep_profile.virtual_server = self.dep_virtual_server
        try:
            add_dep_profile(dep_profile)
        except DEPClientError as error:
            form.add_error(None, str(error))
            return self.form_invalid(form)
        return HttpResponseRedirect(dep_profile.get_absolute_url())


class DEPProfileView(LoginRequiredMixin, DetailView):
    model = DEPProfile


class CheckDEPProfileView(LoginRequiredMixin, DetailView):
    model = DEPProfile
    template_name = "mdm/depprofile_check.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        dep_client = DEPClient.from_dep_virtual_server(self.object.virtual_server)
        ctx["fetched_profile"] = dep_client.get_profile(self.object.uuid)
        return ctx


class UpdateDEPProfileView(LoginRequiredMixin, UpdateView):
    model = DEPProfile
    form_class = DEPProfileForm

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["dep_virtual_server"] = self.object.virtual_server
        return ctx

    def get_initial(self):
        initial = super().get_initial()
        if self.object:
            initial["meta_business_unit"] = self.object.get_meta_business_unit().pk
        return initial

    def form_valid(self, form):
        dep_profile = form.save(commit=False)
        try:
            add_dep_profile(dep_profile)
        except DEPClientError as error:
            form.add_error(None, str(error))
            return self.form_invalid(form)
        return HttpResponseRedirect(dep_profile.get_absolute_url())


class AssignDEPDeviceProfileView(LoginRequiredMixin, UpdateView):
    model = DEPDevice
    form_class = AssignDEPDeviceProfileForm

    def form_valid(self, form):
        dep_device = form.save(commit=False)
        try:
            assign_dep_device_profile(dep_device, dep_device.profile)
        except DEPClientError as e:
            form.add_error(None, str(e))
            return self.form_invalid(form)
        else:
            messages.info(self.request, "Profile {} successfully assigned to device {}.".format(
                dep_device.profile, dep_device.serial_number
            ))
            return HttpResponseRedirect(dep_device.get_absolute_url())
