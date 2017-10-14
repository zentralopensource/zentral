import base64
import logging
from asn1crypto import csr
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import SuspiciousOperation
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.views.generic import CreateView, DetailView, ListView, TemplateView, View
from zentral.contrib.inventory.exceptions import EnrollmentSecretVerificationFailed
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.inventory.utils import verify_enrollment_secret
from zentral.contrib.mdm.cms import sign_payload_openssl
from zentral.contrib.mdm.forms import OTAEnrollmentForm, OTAEnrollmentSecretForm, PushCertificateForm
from zentral.contrib.mdm.models import (MetaBusinessUnitPushCertificate, PushCertificate,
                                        OTAEnrollment, OTAEnrollmentSession)
from zentral.contrib.mdm.payloads import (build_payload_response,
                                          build_root_ca_configuration_profile,
                                          build_profile_service_payload)
from zentral.utils.api_views import SignedRequestHeaderJSONPostAPIView

logger = logging.getLogger('zentral.contrib.mdm.views.setup')


class RootCAView(View):
    def get(self, request, *args, **kwargs):
        return build_payload_response(sign_payload_openssl(build_root_ca_configuration_profile()), "zentral_root_ca")


class EnrollmentView(LoginRequiredMixin, TemplateView):
    template_name = "mdm/enrollment.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        return ctx


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


class VerifySCEPCSRView(SignedRequestHeaderJSONPostAPIView):
    verify_module = "zentral"

    def do_post(self, data):
        csr_data = base64.b64decode(data["csr"].encode("ascii"))
        csr_info = csr.CertificationRequest.load(csr_data)["certification_request_info"]

        csr_d = {}

        # subject
        for rdn_idx, rdn in enumerate(csr_info["subject"].chosen):
            for type_val_idx, type_val in enumerate(rdn):
                csr_d[type_val["type"].native] = type_val['value'].native

        kwargs = {"user_agent": self.user_agent,
                  "public_ip_address": self.ip}

        # serial number
        serial_number = csr_d.get("serial_number")
        if not serial_number:
            raise SuspiciousOperation("Could not get serial number")
        kwargs["serial_number"] = serial_number

        # meta business
        organization_name = csr_d.get("organization_name")
        if not organization_name or not organization_name.startswith("MBU$"):
            raise SuspiciousOperation("Unknown organization name format")
        meta_business_unit_id = int(organization_name.split("$", 1)[-1])
        kwargs["meta_business_unit"] = get_object_or_404(MetaBusinessUnit, pk=meta_business_unit_id)

        # type and session secret
        try:
            cn_prefix, ota_enrollment_session_secret = csr_d["common_name"].split("$")
        except (KeyError, ValueError, AttributeError):
            raise SuspiciousOperation("Unknown common name format")

        # CN prefix => OTA enrollment phase
        if cn_prefix == "OTA":
            ota_enrollment_session_status = OTAEnrollmentSession.PHASE_2
        elif cn_prefix == "MDM":
            ota_enrollment_session_status = OTAEnrollmentSession.PHASE_3
        else:
            raise SuspiciousOperation("Unknown CN prefix {}".format(cn_prefix))

        kwargs["model"] = "ota_enrollment_session"
        kwargs["ota_enrollment_session__status"] = ota_enrollment_session_status
        kwargs["secret"] = ota_enrollment_session_secret

        try:
            es_request = verify_enrollment_secret(**kwargs)
        except EnrollmentSecretVerificationFailed as e:
            raise SuspiciousOperation("secret verification failed: '{}'".format(e.err_msg))
        else:
            # update ota enrollment session
            ota_enrollment_session = es_request.enrollment_secret.ota_enrollment_session
            if ota_enrollment_session_status == OTAEnrollmentSession.PHASE_2:
                ota_enrollment_session.set_phase2_scep_verified_status(es_request)
            if ota_enrollment_session_status == OTAEnrollmentSession.PHASE_3:
                ota_enrollment_session.set_phase3_scep_verified_status(es_request)

        # OK
        return {"status": 0}
