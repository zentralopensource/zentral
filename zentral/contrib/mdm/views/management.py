import logging
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib import messages
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.views.generic import CreateView, DetailView, TemplateView, UpdateView, View
from zentral.contrib.mdm.apns import send_device_notification
from zentral.contrib.mdm.forms import DeviceSearchForm
from zentral.contrib.mdm.models import (EnrolledDevice, DEPDevice, DEPEnrollmentSession, OTAEnrollmentSession,
                                        KernelExtensionPolicy, KernelExtensionTeam, KernelExtension)

logger = logging.getLogger('zentral.contrib.mdm.views.management')


class DevicesView(LoginRequiredMixin, TemplateView):
    template_name = "mdm/device_list.html"

    def get(self, request, *args, **kwargs):
        self.form = DeviceSearchForm(request.GET)
        self.form.is_valid()
        self.devices = list(self.form.fetch_devices())
        if len(self.devices) == 1:
            return HttpResponseRedirect(reverse("mdm:device", args=(self.devices[0]["serial_number"],)))
        return super().get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["mdm"] = True
        ctx["form"] = self.form
        ctx["devices"] = self.devices
        ctx["devices_count"] = len(self.devices)
        bc = [(reverse("mdm:index"), "MDM setup")]
        if not self.form.is_initial():
            bc.extend([(reverse("mdm:devices"), "Devices"),
                       (None, "Search")])
        else:
            bc.extend([(None, "Devices")])
        ctx["breadcrumbs"] = bc
        return ctx


class DeviceView(LoginRequiredMixin, TemplateView):
    template_name = "mdm/device_info.html"

    def get_context_data(self, **kwargs):
        serial_number = kwargs["serial_number"]
        ctx = super().get_context_data(**kwargs)
        ctx["serial_number"] = serial_number
        ctx["mdm"] = True
        # enrolled devices
        ctx["enrolled_devices"] = EnrolledDevice.objects.filter(serial_number=serial_number).order_by("-updated_at")
        ctx["enrolled_devices_count"] = ctx["enrolled_devices"].count()
        # dep device?
        try:
            ctx["dep_device"] = DEPDevice.objects.get(serial_number=serial_number)
        except DEPDevice.DoesNotExist:
            pass
        # dep enrollment sessions
        ctx["dep_enrollment_sessions"] = DEPEnrollmentSession.objects.filter(
            enrollment_secret__serial_numbers__contains=[serial_number]
        ).order_by("-updated_at")
        ctx["dep_enrollment_sessions_count"] = ctx["dep_enrollment_sessions"].count()
        # ota enrollment sessions
        ctx["ota_enrollment_sessions"] = OTAEnrollmentSession.objects.filter(
            enrollment_secret__serial_numbers__contains=[serial_number]
        ).order_by("-updated_at")
        ctx["ota_enrollment_sessions_count"] = ctx["ota_enrollment_sessions"].count()
        return ctx


class PokeEnrolledDeviceView(LoginRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        enrolled_device = get_object_or_404(EnrolledDevice, pk=kwargs["pk"])
        send_device_notification(enrolled_device)
        messages.info(request, "Device poked!")
        return HttpResponseRedirect(reverse("mdm:device", args=(enrolled_device.serial_number,)))


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
        ctx["kernel_extension_policies"] = KernelExtensionPolicy.objects.all()
        ctx["kernel_extension_policies_count"] = ctx["kernel_extension_policies"].count()
        return ctx


class CreateKernelExtensionTeamView(LoginRequiredMixin, CreateView):
    model = KernelExtensionTeam
    fields = "__all__"

    def form_valid(self, form):
        messages.info(self.request, "Kernel extension team created.")
        return super().form_valid(form)


class CreateKernelExtensionView(LoginRequiredMixin, CreateView):
    model = KernelExtension
    fields = "__all__"

    def form_valid(self, form):
        messages.info(self.request, "Kernel extension created.")
        return super().form_valid(form)


class CreateKernelExtensionPolicyView(LoginRequiredMixin, CreateView):
    model = KernelExtensionPolicy
    fields = "__all__"


class KernelExtensionPolicyView(LoginRequiredMixin, DetailView):
    model = KernelExtensionPolicy


class UpdateKernelExtensionPolicyView(LoginRequiredMixin, UpdateView):
    model = KernelExtensionPolicy
    fields = "__all__"
