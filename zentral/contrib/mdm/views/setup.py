import io
import logging
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import FileResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.views.generic import CreateView, DetailView, ListView, TemplateView, UpdateView, View
from zentral.contrib.mdm.dep import add_dep_token_certificate
from zentral.contrib.mdm.forms import (EncryptedDEPTokenForm,
                                       PushCertificateForm,
                                       AddPushCertificateBusinessUnitForm)
from zentral.contrib.mdm.models import (MetaBusinessUnitPushCertificate, PushCertificate,
                                        DEPProfile, DEPToken, DEPVirtualServer,
                                        KernelExtensionTeam, KernelExtension,
                                        OTAEnrollment)
from zentral.contrib.mdm.payloads import (build_configuration_profile_response,
                                          build_root_ca_configuration_profile)

logger = logging.getLogger('zentral.contrib.mdm.views.setup')


class IndexView(LoginRequiredMixin, TemplateView):
    template_name = "mdm/index.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        return ctx


class RootCAView(View):
    def get(self, request, *args, **kwargs):
        return build_configuration_profile_response(build_root_ca_configuration_profile(), "zentral_root_ca")


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
    form_class = AddPushCertificateBusinessUnitForm

    def dispatch(self, request, *args, **kwargs):
        self.push_certificate = get_object_or_404(PushCertificate, pk=kwargs["pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["push_certificate"] = self.push_certificate
        return kwargs

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


class RemovePushCertificateBusinessUnitView(LoginRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        mbups = get_object_or_404(
            MetaBusinessUnitPushCertificate,
            push_certificate__pk=kwargs["pk"],
            meta_business_unit__pk=request.POST["meta_business_unit"]
        )
        meta_business_unit = mbups.meta_business_unit
        push_certificate = mbups.push_certificate
        mbups.delete()
        messages.info(request, "Removed business unit {} from push certificate".format(meta_business_unit))
        return HttpResponseRedirect(push_certificate.get_absolute_url())


# OTA enrollment


class OTAEnrollmentListView(LoginRequiredMixin, ListView):
    def get_queryset(self):
        return (OTAEnrollment.objects.select_related("enrollment_secret__meta_business_unit")
                                     .order_by("name")
                                     .all())

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        return ctx


# DEP Tokens


class DownloadDEPTokenPublicKeyView(LoginRequiredMixin, View):
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


class RenewDEPTokenView(LoginRequiredMixin, UpdateView):
    model = DEPToken
    template_name = "mdm/deptoken_renew.html"
    form_class = EncryptedDEPTokenForm

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["setup"] = True
        try:
            context["virtual_server"] = context["object"].virtual_server
        except DEPVirtualServer.DoesNotExist:
            context["virtual_server"] = None
        return context

    def form_valid(self, form):
        dep_token = form.save()
        return HttpResponseRedirect(dep_token.virtual_server.get_absolute_url())


# DEP virtual servers


class DEPVirtualServersView(LoginRequiredMixin, ListView):
    model = DEPVirtualServer

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["setup"] = True
        return context


class ConnectDEPVirtualServerView(LoginRequiredMixin, View):
    template_name = "mdm/depvirtualserver_connect.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["setup"] = True
        return context

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
        self.get_or_create_current_dep_token(request)
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


class DEPVirtualServerView(LoginRequiredMixin, DetailView):
    model = DEPVirtualServer

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["setup"] = True
        return context

# DEP profiles


class DEPProfilesView(LoginRequiredMixin, ListView):
    def get_queryset(self):
        return (DEPProfile.objects.select_related("enrollment_secret__meta_business_unit")
                                  .order_by("name")
                                  .all())

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        return ctx

# Kernel extensions


class KernelExtensionsIndexView(LoginRequiredMixin, TemplateView):
    template_name = "mdm/kernel_extensions_index.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["kernel_extension_teams"] = KernelExtensionTeam.objects.all()
        ctx["kernel_extension_teams_count"] = ctx["kernel_extension_teams"].count()
        ctx["kernel_extensions"] = KernelExtension.objects.all()
        ctx["kernel_extensions_count"] = ctx["kernel_extensions"].count()
        return ctx


class CreateKernelExtensionTeamView(LoginRequiredMixin, CreateView):
    model = KernelExtensionTeam
    fields = "__all__"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        return ctx

    def form_valid(self, form):
        messages.info(self.request, "Kernel extension team created.")
        return super().form_valid(form)


class CreateKernelExtensionView(LoginRequiredMixin, CreateView):
    model = KernelExtension
    fields = "__all__"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        return ctx

    def form_valid(self, form):
        messages.info(self.request, "Kernel extension created.")
        return super().form_valid(form)
