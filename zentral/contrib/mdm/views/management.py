import logging
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib import messages
from django.db import transaction
from django.http import Http404, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.views.generic import CreateView, DetailView, TemplateView, UpdateView, View
from zentral.contrib.inventory.forms import EnrollmentSecretForm, MetaBusinessUnit
from zentral.contrib.mdm.events import send_device_notification, send_mbu_device_notifications
from zentral.contrib.mdm.forms import DeviceSearchForm
from zentral.contrib.mdm.models import (EnrolledDevice, DEPDevice, DEPEnrollmentSession, OTAEnrollmentSession,
                                        KernelExtensionPolicy, KernelExtensionTeam, KernelExtension,
                                        MDMEnrollmentPackage)
from zentral.utils.osx_package import get_standalone_package_builders

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

    def form_valid(self, form):
        kext_policy = form.save()
        transaction.on_commit(lambda: send_mbu_device_notifications(kext_policy.meta_business_unit))
        return HttpResponseRedirect(kext_policy.get_absolute_url())


class KernelExtensionPolicyView(LoginRequiredMixin, DetailView):
    model = KernelExtensionPolicy


class UpdateKernelExtensionPolicyView(LoginRequiredMixin, UpdateView):
    model = KernelExtensionPolicy
    fields = "__all__"

    def form_valid(self, form):
        kext_policy = form.save()
        transaction.on_commit(lambda: send_mbu_device_notifications(kext_policy.meta_business_unit))
        return HttpResponseRedirect(kext_policy.get_absolute_url())


# Enrollment Packages


class CreateEnrollmentPackageView(LoginRequiredMixin, TemplateView):
    template_name = "mdm/mdmenrollmentpackage_form.html"

    def dispatch(self, request, *args, **kwargs):
        standalone_builders = get_standalone_package_builders()
        self.meta_business_unit = get_object_or_404(MetaBusinessUnit, pk=kwargs["pk"])
        try:
            self.builder_key = request.GET["builder"]
            self.builder = standalone_builders[self.builder_key]
        except KeyError:
            raise Http404
        return super().dispatch(request, *args, **kwargs)

    def get_forms(self):
        secret_form_kwargs = {"prefix": "secret",
                              "no_restrictions": True,
                              "meta_business_unit": self.meta_business_unit}
        enrollment_form_kwargs = {"standalone": True}  # w/o dependencies. all in the package.
        if self.request.method == "POST":
            secret_form_kwargs["data"] = self.request.POST
            enrollment_form_kwargs["data"] = self.request.POST
        return (EnrollmentSecretForm(**secret_form_kwargs),
                self.builder.form(**enrollment_form_kwargs))

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["setup"] = True
        context["title"] = "Create enrollment package"
        context["meta_business_unit"] = self.meta_business_unit
        context["builder_name"] = self.builder.name
        if "secret_form" not in kwargs or "enrollment_form" not in kwargs:
            context["secret_form"], context["enrollment_form"] = self.get_forms()
        return context

    def forms_invalid(self, secret_form, enrollment_form):
        return self.render_to_response(self.get_context_data(secret_form=secret_form,
                                                             enrollment_form=enrollment_form))

    def forms_valid(self, secret_form, enrollment_form):
        # make secret
        secret = secret_form.save()
        # make enrollment
        enrollment = enrollment_form.save(commit=False)
        enrollment.version = 0
        enrollment.secret = secret
        enrollment.save()
        # MDM enrollment package
        mep = MDMEnrollmentPackage.objects.create(
            meta_business_unit=secret.meta_business_unit,
            builder=self.builder_key,
            enrollment_pk=enrollment.pk
        )
        # link from enrollment to mdm enrollment package, for config update propagation
        enrollment.distributor = mep
        enrollment.save()  # build package and package manifest via callback call
        transaction.on_commit(lambda: send_mbu_device_notifications(mep.meta_business_unit))
        return HttpResponseRedirect(mep.get_absolute_url())

    def post(self, request, *args, **kwargs):
        secret_form, enrollment_form = self.get_forms()
        if secret_form.is_valid() and enrollment_form.is_valid():
            return self.forms_valid(secret_form, enrollment_form)
        else:
            return self.forms_invalid(secret_form, enrollment_form)
