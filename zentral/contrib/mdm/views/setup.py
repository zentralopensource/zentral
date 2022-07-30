import io
import logging
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.core.exceptions import SuspiciousOperation
from django.http import FileResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.urls import reverse, reverse_lazy
from django.views.generic import CreateView, DeleteView, DetailView, ListView, TemplateView, UpdateView, View
from zentral.contrib.mdm.dep import add_dep_token_certificate
from zentral.contrib.mdm.forms import EncryptedDEPTokenForm, PushCertificateForm
from zentral.contrib.mdm.models import PushCertificate, DEPToken, DEPVirtualServer
from zentral.contrib.mdm.payloads import (build_configuration_profile_response,
                                          build_root_ca_configuration_profile)

logger = logging.getLogger('zentral.contrib.mdm.views.setup')


class IndexView(LoginRequiredMixin, TemplateView):
    template_name = "mdm/index.html"


class RootCAView(View):
    def get(self, request, *args, **kwargs):
        return build_configuration_profile_response(build_root_ca_configuration_profile(), "zentral_root_ca")


# Push certificates


class PushCertificatesView(PermissionRequiredMixin, ListView):
    permission_required = "mdm.view_pushcertificate"
    model = PushCertificate


class AddPushCertificateView(PermissionRequiredMixin, CreateView):
    permission_required = "mdm.add_pushcertificate"
    model = PushCertificate
    form_class = PushCertificateForm


class PushCertificateView(PermissionRequiredMixin, DetailView):
    permission_required = "mdm.view_pushcertificate"
    model = PushCertificate

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["dep_enrollments"] = list(self.object.depenrollment_set.all().order_by("-pk"))
        ctx["ota_enrollments"] = list(self.object.otaenrollment_set.all().order_by("-pk"))
        ctx["user_enrollments"] = list(self.object.userenrollment_set.all().order_by("-pk"))
        return ctx


class UpdatePushCertificateView(PermissionRequiredMixin, UpdateView):
    permission_required = "mdm.change_pushcertificate"
    model = PushCertificate
    form_class = PushCertificateForm


class DeletePushCertificateView(PermissionRequiredMixin, DeleteView):
    permission_required = "mdm.delete_pushcertificate"
    model = PushCertificate
    success_url = reverse_lazy("mdm:push_certificates")

    def get_object(self, queryset=None):
        obj = super().get_object(queryset)
        if not obj.can_be_deleted():
            raise SuspiciousOperation("This push certificate cannot be deleted")
        return obj


# DEP Tokens


class DownloadDEPTokenPublicKeyView(PermissionRequiredMixin, View):
    permission_required = "mdm.add_depvirtualserver"

    def get(self, request, *args, **kwargs):
        dep_token = get_object_or_404(DEPToken, pk=kwargs["pk"], consumer_key__isnull=True)
        certificate = dep_token.certificate
        if isinstance(certificate, memoryview):
            certificate = certificate.tobytes()
        filename = "{}_public_key_{}_{}.pem".format(
            request.get_host(),
            dep_token.pk,
            dep_token.created_at.strftime("%Y%m%d%H%M%S")
        )
        return FileResponse(io.BytesIO(certificate),
                            content_type="application/x-pem-file",
                            as_attachment=True,
                            filename=filename)


class RenewDEPTokenView(PermissionRequiredMixin, UpdateView):
    permission_required = "mdm.change_depvirtualserver"
    model = DEPToken
    template_name = "mdm/deptoken_renew.html"
    form_class = EncryptedDEPTokenForm

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        try:
            context["virtual_server"] = context["object"].virtual_server
        except DEPVirtualServer.DoesNotExist:
            context["virtual_server"] = None
        return context

    def form_valid(self, form):
        dep_token = form.save()
        return HttpResponseRedirect(dep_token.virtual_server.get_absolute_url())


# DEP virtual servers


class DEPVirtualServersView(PermissionRequiredMixin, ListView):
    permission_required = "mdm.view_depvirtualserver"
    model = DEPVirtualServer


class ConnectDEPVirtualServerView(PermissionRequiredMixin, View):
    permission_required = "mdm.add_depvirtualserver"
    template_name = "mdm/depvirtualserver_connect.html"

    def get_or_create_current_dep_token(self, request):
        self.current_dep_token = None
        current_dep_token_id = request.session.get("current_dep_token_id")
        if current_dep_token_id:
            try:
                self.current_dep_token = DEPToken.objects.get(pk=current_dep_token_id)
            except DEPToken.DoesNotExist:
                # the token id in the session is invalid. remove it.
                request.session.pop("current_dep_token_id")
            else:
                # verify that the current dep token has no attached server.
                try:
                    virtual_server = self.current_dep_token.virtual_server
                except DEPVirtualServer.DoesNotExist:
                    pass
                else:
                    # the current token already has a server.
                    # remove it from the session and redirect to the server.
                    request.session.pop("current_dep_token_id")
                    return HttpResponseRedirect(virtual_server.get_absolute_url())
        if not self.current_dep_token:
            # create a new one, and attach it to the session
            self.current_dep_token = DEPToken.objects.create()
            add_dep_token_certificate(self.current_dep_token)
            request.session["current_dep_token_id"] = self.current_dep_token.pk

    def do_cancel(self, request):
        self.current_dep_token.delete()
        request.session.pop("current_dep_token_id")
        return HttpResponseRedirect(reverse("mdm:dep_virtual_servers"))

    def post(self, request, *args, **kwargs):
        response = self.get_or_create_current_dep_token(request)
        if response:
            return response
        action = request.POST.get("action", None)
        if action == "cancel":
            return self.do_cancel(request)
        elif action == "upload":
            form = EncryptedDEPTokenForm(instance=self.current_dep_token,
                                         data=request.POST, files=request.FILES)
            if form.is_valid():
                dep_token = form.save()
                request.session.pop("current_dep_token_id")
                return HttpResponseRedirect(dep_token.virtual_server.get_absolute_url())
        else:
            # start
            form = EncryptedDEPTokenForm(instance=self.current_dep_token)
        return render(request, "mdm/depvirtualserver_connect.html",
                      {"setup": True,
                       "dep_token": self.current_dep_token,
                       "form": form})

    def get(self, request, *args, **kwargs):
        return HttpResponseRedirect(reverse("mdm:dep_virtual_servers"))


class DEPVirtualServerView(PermissionRequiredMixin, DetailView):
    permission_required = "mdm.view_depvirtualserver"
    model = DEPVirtualServer

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["setup"] = True
        return context
