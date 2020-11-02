import logging
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib import messages
from django.core.exceptions import SuspiciousOperation
from django.db import transaction
from django.http import Http404, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.utils import timezone
from django.views.generic import CreateView, DeleteView, DetailView, FormView, TemplateView, UpdateView, View
from realms.models import RealmUser
from zentral.contrib.inventory.forms import EnrollmentSecretForm
from zentral.contrib.inventory.models import MetaBusinessUnit, MetaMachine
from zentral.contrib.mdm.dep import add_dep_profile, assign_dep_device_profile, refresh_dep_device
from zentral.contrib.mdm.dep_client import DEPClient, DEPClientError
from zentral.contrib.mdm.forms import (AssignDEPDeviceProfileForm, DeviceSearchForm,
                                       CreateDEPProfileForm, UpdateDEPProfileForm, OTAEnrollmentForm,
                                       UploadConfigurationProfileForm)
from zentral.contrib.mdm.models import (MetaBusinessUnitPushCertificate,
                                        EnrolledDevice,
                                        DEPDevice, DEPEnrollmentSession, DEPProfile,
                                        OTAEnrollment, OTAEnrollmentSession,
                                        KernelExtensionPolicy, MDMEnrollmentPackage, ConfigurationProfile)
from zentral.contrib.mdm.payloads import (build_configuration_profile_response,
                                          build_profile_service_configuration_profile)
from zentral.contrib.mdm.tasks import send_enrolled_device_notification, send_mbu_enrolled_devices_notifications
from zentral.utils.osx_package import get_standalone_package_builders

logger = logging.getLogger('zentral.contrib.mdm.views.management')


# Meta business units


class MetaBusinessUnitListView(LoginRequiredMixin, TemplateView):
    template_name = "mdm/metabusinessunit_list.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["mdm"] = True
        context["mbu_list"] = sorted(set(
            mbupc.meta_business_unit
            for mbupc in MetaBusinessUnitPushCertificate.objects.select_related("meta_business_unit").all()
        ), key=lambda mbu: mbu.name)
        return context


class MetaBusinessUnitDetailView(LoginRequiredMixin, DetailView):
    model = MetaBusinessUnit
    template_name = "mdm/metabusinessunit_detail.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data()
        context["mdm"] = True
        mbu = context["object"]
        context["dep_profile_list"] = (DEPProfile.objects.select_related("virtual_server")
                                                         .filter(enrollment_secret__meta_business_unit=mbu)
                                                         .order_by("name", "pk"))
        context["ota_enrollment_list"] = (OTAEnrollment.objects.filter(enrollment_secret__meta_business_unit=mbu)
                                                               .order_by("name", "pk"))
        context["kext_policy_list"] = (KernelExtensionPolicy.objects.filter(meta_business_unit=mbu,
                                                                            trashed_at__isnull=True)
                                                                    .order_by("pk"))
        context["enrollment_package_list"] = (MDMEnrollmentPackage.objects.filter(meta_business_unit=mbu,
                                                                                  trashed_at__isnull=True)
                                                                          .order_by("builder", "pk"))
        existing_enrollment_package_builders = [ep.builder for ep in context["enrollment_package_list"]]
        create_enrollment_package_url = reverse("mdm:create_enrollment_package", args=(mbu.pk,))
        context["create_enrollment_package_links"] = [("{}?builder={}".format(create_enrollment_package_url, k),
                                                       v.name)
                                                      for k, v in get_standalone_package_builders().items()
                                                      if k not in existing_enrollment_package_builders]
        context["configuration_profile_list"] = (ConfigurationProfile.objects.filter(meta_business_unit=mbu,
                                                                                     trashed_at__isnull=True)
                                                                             .order_by("payload_description", "pk"))
        return context


# DEP Profiles


class CreateDEPProfileView(LoginRequiredMixin, TemplateView):
    template_name = "mdm/depprofile_form.html"

    def dispatch(self, request, *args, **kwargs):
        self.meta_business_unit = get_object_or_404(MetaBusinessUnit, pk=kwargs["pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["mdm"] = True
        context["meta_business_unit"] = self.meta_business_unit
        dep_profile_form = kwargs.get("dep_profile_form")
        if not dep_profile_form:
            dep_profile_form = CreateDEPProfileForm(prefix="dp")
        context["dep_profile_form"] = dep_profile_form
        enrollment_secret_form = kwargs.get("enrollment_secret_form")
        if not enrollment_secret_form:
            enrollment_secret_form = EnrollmentSecretForm(
                prefix="es",
                no_restrictions=True,
                meta_business_unit=self.meta_business_unit,
            )
        context["enrollment_secret_form"] = enrollment_secret_form
        return context

    def post(self, request, *args, **kwargs):
        dep_profile_form = CreateDEPProfileForm(request.POST, prefix="dp")
        enrollment_secret_form = EnrollmentSecretForm(
            request.POST,
            prefix="es",
            no_restrictions=True,
            meta_business_unit=self.meta_business_unit,
        )
        if dep_profile_form.is_valid() and enrollment_secret_form.is_valid():
            dep_profile = dep_profile_form.save(commit=False)
            dep_profile.enrollment_secret = enrollment_secret_form.save()
            enrollment_secret_form.save_m2m()
            try:
                add_dep_profile(dep_profile)
            except DEPClientError as error:
                dep_profile_form.add_error(None, str(error))
            else:
                return HttpResponseRedirect(dep_profile.get_absolute_url())
        return self.render_to_response(
            self.get_context_data(dep_profile_form=dep_profile_form,
                                  enrollment_secret_form=enrollment_secret_form)
        )


class DEPProfileView(LoginRequiredMixin, DetailView):
    model = DEPProfile

    def get_queryset(self):
        return DEPProfile.objects.filter(enrollment_secret__meta_business_unit__pk=self.kwargs["mbu_pk"])

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["mdm"] = True
        ctx["meta_business_unit"] = self.object.get_meta_business_unit()
        return ctx


class CheckDEPProfileView(LoginRequiredMixin, DetailView):
    model = DEPProfile
    template_name = "mdm/depprofile_check.html"

    def get_queryset(self):
        return DEPProfile.objects.filter(enrollment_secret__meta_business_unit__pk=self.kwargs["mbu_pk"])

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["mdm"] = True
        ctx["meta_business_unit"] = self.object.get_meta_business_unit()
        dep_client = DEPClient.from_dep_virtual_server(self.object.virtual_server)
        ctx["fetched_profile"] = dep_client.get_profile(self.object.uuid)
        return ctx


class UpdateDEPProfileView(LoginRequiredMixin, TemplateView):
    template_name = "mdm/depprofile_form.html"

    def dispatch(self, request, *args, **kwargs):
        self.object = get_object_or_404(
            DEPProfile,
            enrollment_secret__meta_business_unit__pk=kwargs["mbu_pk"],
            pk=kwargs["pk"]
        )
        self.meta_business_unit = self.object.get_meta_business_unit()
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["mdm"] = True
        context["object"] = self.object
        context["meta_business_unit"] = self.meta_business_unit
        dep_profile_form = kwargs.get("dep_profile_form")
        if not dep_profile_form:
            dep_profile_form = UpdateDEPProfileForm(prefix="dp",
                                                    instance=self.object)
        context["dep_profile_form"] = dep_profile_form
        enrollment_secret_form = kwargs.get("enrollment_secret_form")
        if not enrollment_secret_form:
            enrollment_secret_form = EnrollmentSecretForm(
                prefix="es",
                instance=self.object.enrollment_secret,
                no_restrictions=True,
                meta_business_unit=self.meta_business_unit,
            )
        context["enrollment_secret_form"] = enrollment_secret_form
        return context

    def post(self, request, *args, **kwargs):
        dep_profile_form = UpdateDEPProfileForm(
            request.POST,
            prefix="dp",
            instance=self.object
        )
        enrollment_secret_form = EnrollmentSecretForm(
            request.POST,
            prefix="es",
            instance=self.object.enrollment_secret,
            no_restrictions=True,
            meta_business_unit=self.meta_business_unit,
        )
        if dep_profile_form.is_valid() and enrollment_secret_form.is_valid():
            dep_profile = dep_profile_form.save(commit=False)
            dep_profile.enrollment_secret = enrollment_secret_form.save()
            enrollment_secret_form.save_m2m()
            try:
                add_dep_profile(dep_profile)
            except DEPClientError as error:
                dep_profile_form.add_error(None, str(error))
            else:
                return HttpResponseRedirect(dep_profile.get_absolute_url())
        return self.render_to_response(
            self.get_context_data(dep_profile_form=dep_profile_form,
                                  enrollment_secret_form=enrollment_secret_form)
        )

# OTA Enrollments


class CreateOTAEnrollmentView(LoginRequiredMixin, TemplateView):
    template_name = "mdm/create_ota_enrollment.html"

    def dispatch(self, request, *args, **kwargs):
        self.meta_business_unit = get_object_or_404(MetaBusinessUnit, pk=kwargs["pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["mdm"] = True
        context["meta_business_unit"] = self.meta_business_unit
        ota_enrollment_form = kwargs.get("ota_enrollment_form")
        if not ota_enrollment_form:
            ota_enrollment_form = OTAEnrollmentForm(prefix="oe")
        context["ota_enrollment_form"] = ota_enrollment_form
        enrollment_secret_form = kwargs.get("enrollment_secret_form")
        if not enrollment_secret_form:
            enrollment_secret_form = EnrollmentSecretForm(
                prefix="es",
                meta_business_unit=self.meta_business_unit,
            )
        context["enrollment_secret_form"] = enrollment_secret_form
        return context

    def post(self, request, *args, **kwargs):
        ota_enrollment_form = OTAEnrollmentForm(request.POST, prefix="oe")
        enrollment_secret_form = EnrollmentSecretForm(
            request.POST,
            prefix="es",
            meta_business_unit=self.meta_business_unit,
        )
        if ota_enrollment_form.is_valid() and enrollment_secret_form.is_valid():
            ota_enrollment = ota_enrollment_form.save(commit=False)
            ota_enrollment.enrollment_secret = enrollment_secret_form.save()
            enrollment_secret_form.save_m2m()
            ota_enrollment.save()
            return HttpResponseRedirect(ota_enrollment.get_absolute_url())
        else:
            return self.render_to_response(
                self.get_context_data(ota_enrollment_form=ota_enrollment_form,
                                      enrollment_secret_form=enrollment_secret_form)
            )


class OTAEnrollmentView(LoginRequiredMixin, DetailView):
    template_name = "mdm/ota_enrollment.html"
    model = OTAEnrollment

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["mdm"] = True
        ota_enrollment = ctx["object"]
        ctx["meta_business_unit"] = ota_enrollment.enrollment_secret.meta_business_unit
        ctx["enroll_url"] = ota_enrollment.get_enroll_full_url()
        # TODO: pagination
        ctx["ota_enrollment_sessions"] = (ctx["object"].otaenrollmentsession_set.all()
                                                       .select_related("enrollment_secret")
                                                       .order_by("-created_at"))
        ctx["ota_enrollment_sessions_count"] = ctx["ota_enrollment_sessions"].count()
        return ctx


class DownloadProfileServicePayloadView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        ota_enrollment = get_object_or_404(
            OTAEnrollment,
            enrollment_secret__meta_business_unit__pk=kwargs["mbu_pk"],
            pk=kwargs["pk"],
            realm__isnull=True
        )
        if not ota_enrollment.enrollment_secret.is_valid():
            # should not happen
            raise SuspiciousOperation
        return build_configuration_profile_response(
            build_profile_service_configuration_profile(ota_enrollment),
            "zentral_profile_service"
        )


class RevokeOTAEnrollmentView(LoginRequiredMixin, TemplateView):
    template_name = "mdm/revoke_ota_enrollment.html"

    def dispatch(self, request, *args, **kwargs):
        self.ota_enrollment = get_object_or_404(
            OTAEnrollment,
            enrollment_secret__meta_business_unit__pk=kwargs["mbu_pk"],
            pk=kwargs["pk"]
        )
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["mdm"] = True
        ctx["ota_enrollment"] = self.ota_enrollment
        ctx["meta_business_unit"] = self.ota_enrollment.enrollment_secret.meta_business_unit
        return ctx

    def post(self, request, *args, **kwargs):
        self.ota_enrollment.revoke()
        return HttpResponseRedirect(self.ota_enrollment.get_absolute_url())


def ota_enroll_callback(request, realm_authentication_session, ota_enrollment_pk):
    """
    Realm authorization session callback used to start authenticated OTAEnrollmentSession
    """
    ota_enrollment = OTAEnrollment.objects.get(pk=ota_enrollment_pk, realm__isnull=False)
    realm_user = realm_authentication_session.user
    request.session["_ota_{}_realm_user_pk".format(ota_enrollment.pk)] = str(realm_user.pk)
    return reverse("mdm:ota_enrollment_enroll",
                   args=(ota_enrollment.enrollment_secret.meta_business_unit.pk,
                         ota_enrollment.pk))


class OTAEnrollmentEnrollView(View):
    def get(self, request, *args, **kwargs):
        ota_enrollment = get_object_or_404(
            OTAEnrollment,
            enrollment_secret__meta_business_unit__pk=kwargs["mbu_pk"],
            pk=kwargs["pk"],
            realm__isnull=False
        )
        if not ota_enrollment.enrollment_secret.is_valid():
            # should not happen
            raise SuspiciousOperation
        # check the auth
        try:
            realm_user_pk = self.request.session.pop("_ota_{}_realm_user_pk".format(ota_enrollment.pk))
            realm_user = RealmUser.objects.get(realm=ota_enrollment.realm,
                                               pk=realm_user_pk)
        except (KeyError, RealmUser.DoesNotExist):
            # start realm auth session, do redirect
            callback = "zentral.contrib.mdm.views.management.ota_enroll_callback"
            callback_kwargs = {"ota_enrollment_pk": ota_enrollment.pk}
            return HttpResponseRedirect(
                ota_enrollment.realm.backend_instance.initialize_session(callback, **callback_kwargs)
            )
        else:
            ota_enrollment_session = OTAEnrollmentSession.objects.create_from_realm_user(ota_enrollment, realm_user)
            # start OTAEnrollmentSession, build config profile, return config profile
            return build_configuration_profile_response(
                build_profile_service_configuration_profile(ota_enrollment_session),
                "zentral_profile_service"
            )


# kernel extension policies


class CreateKernelExtensionPolicyView(LoginRequiredMixin, CreateView):
    model = KernelExtensionPolicy
    fields = "__all__"

    def dispatch(self, request, *args, **kwargs):
        self.meta_business_unit = get_object_or_404(MetaBusinessUnit, pk=kwargs["pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["mdm"] = True
        context["meta_business_unit"] = self.meta_business_unit
        return context

    def form_valid(self, form):
        existing_kext_policies = (KernelExtensionPolicy.objects.select_for_update()
                                                               .filter(meta_business_unit=self.meta_business_unit))
        # there should be at most a trashed one.
        try:
            instance = existing_kext_policies[0]
        except IndexError:
            pass
        else:
            form.instance = instance
        kext_policy = form.save(commit=False)
        kext_policy.meta_business_unit = self.meta_business_unit
        kext_policy.trashed_at = None
        kext_policy.save()
        form.save_m2m()
        transaction.on_commit(lambda: send_mbu_enrolled_devices_notifications(kext_policy.meta_business_unit))
        return HttpResponseRedirect(kext_policy.get_absolute_url())


class KernelExtensionPolicyView(LoginRequiredMixin, DetailView):
    model = KernelExtensionPolicy

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["mdm"] = True
        return context


class UpdateKernelExtensionPolicyView(LoginRequiredMixin, UpdateView):
    model = KernelExtensionPolicy
    fields = "__all__"

    def dispatch(self, request, *args, **kwargs):
        self.meta_business_unit = get_object_or_404(MetaBusinessUnit, pk=kwargs["mbu_pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["mdm"] = True
        context["meta_business_unit"] = self.meta_business_unit
        return context

    def form_valid(self, form):
        kext_policy = form.save(commit=False)
        kext_policy.meta_business_unit = self.meta_business_unit
        kext_policy.save()
        form.save_m2m()
        transaction.on_commit(lambda: send_mbu_enrolled_devices_notifications(kext_policy.meta_business_unit))
        return HttpResponseRedirect(kext_policy.get_absolute_url())


class TrashKernelExtensionPolicyView(LoginRequiredMixin, DeleteView):
    model = KernelExtensionPolicy

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["mdm"] = True
        return context

    def delete(self, request, *args, **kwargs):
        self.object = self.get_object()
        self.object.trashed_at = timezone.now()
        self.object.save()
        transaction.on_commit(lambda: send_mbu_enrolled_devices_notifications(self.object.meta_business_unit))
        return HttpResponseRedirect(reverse("mdm:mbu", args=(self.object.meta_business_unit.pk,)))


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
        try:
            # test if an active mep exists. protect ourselves if there is a bug and many exist!
            mep = MDMEnrollmentPackage.objects.filter(meta_business_unit=self.meta_business_unit,
                                                      builder=self.builder_key,
                                                      trashed_at__isnull=True)[0]
        except IndexError:
            pass
        else:
            # prevent the creation of a second enrollment package with the same builder
            # if an active enrollment package exists
            messages.error(request,
                           "An active enrollment package for this business unit and this service already exists.")
            return HttpResponseRedirect(mep.get_absolute_url())
        return super().dispatch(request, *args, **kwargs)

    def get_forms(self):
        secret_form_kwargs = {"prefix": "secret",
                              "no_restrictions": True,
                              "meta_business_unit": self.meta_business_unit}
        enrollment_form_kwargs = {"meta_business_unit": self.meta_business_unit,
                                  "standalone": True}  # w/o dependencies. all in the package.
        if self.request.method == "POST":
            secret_form_kwargs["data"] = self.request.POST
            enrollment_form_kwargs["data"] = self.request.POST
        return (EnrollmentSecretForm(**secret_form_kwargs),
                self.builder.form(**enrollment_form_kwargs))

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["mdm"] = True
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
        enrollment_form.save_m2m()
        # MDM enrollment package
        mep = MDMEnrollmentPackage.objects.create(
            meta_business_unit=secret.meta_business_unit,
            builder=self.builder_key,
            enrollment_pk=enrollment.pk
        )
        # link from enrollment to mdm enrollment package, for config update propagation
        enrollment.distributor = mep
        enrollment.save()  # build package and package manifest via callback call
        transaction.on_commit(lambda: send_mbu_enrolled_devices_notifications(mep.meta_business_unit))
        return HttpResponseRedirect(mep.get_absolute_url())

    def post(self, request, *args, **kwargs):
        secret_form, enrollment_form = self.get_forms()
        if secret_form.is_valid() and enrollment_form.is_valid():
            return self.forms_valid(secret_form, enrollment_form)
        else:
            return self.forms_invalid(secret_form, enrollment_form)


class TrashEnrollmentPackageView(LoginRequiredMixin, DeleteView):
    model = MDMEnrollmentPackage

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["mdm"] = True
        return context

    def delete(self, request, *args, **kwargs):
        self.object = self.get_object()
        self.object.trashed_at = timezone.now()
        self.object.save()
        return HttpResponseRedirect(reverse("mdm:mbu", args=(self.object.meta_business_unit.pk,)))


# Configuration Profiles


class UploadConfigurationProfileView(LoginRequiredMixin, FormView):
    model = ConfigurationProfile
    form_class = UploadConfigurationProfileForm
    template_name = "mdm/configurationprofile_form.html"

    def dispatch(self, request, *args, **kwargs):
        self.meta_business_unit = get_object_or_404(MetaBusinessUnit, pk=kwargs["pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["meta_business_unit"] = self.meta_business_unit
        return kwargs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["mdm"] = True
        context["title"] = "upload a configuration profile"
        context["meta_business_unit"] = self.meta_business_unit
        return context

    def form_valid(self, form):
        self.configuration_profile = form.save()
        transaction.on_commit(lambda: send_mbu_enrolled_devices_notifications(self.meta_business_unit))
        return super().form_valid(form)

    def get_success_url(self):
        return self.configuration_profile.get_absolute_url()


class TrashConfigurationProfileView(LoginRequiredMixin, DeleteView):
    model = ConfigurationProfile

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["mdm"] = True
        return context

    def delete(self, request, *args, **kwargs):
        self.object = self.get_object()
        self.object.trashed_at = timezone.now()
        self.object.save()
        transaction.on_commit(lambda: send_mbu_enrolled_devices_notifications(self.object.meta_business_unit))
        return HttpResponseRedirect(reverse("mdm:mbu", args=(self.object.meta_business_unit.pk,)))


# Devices


class DevicesView(LoginRequiredMixin, TemplateView):
    template_name = "mdm/device_list.html"

    def get(self, request, *args, **kwargs):
        self.form = DeviceSearchForm(request.GET)
        self.form.is_valid()
        self.devices = list(self.form.fetch_devices())
        if len(self.devices) == 1:
            return HttpResponseRedirect(reverse("mdm:device", args=(self.devices[0]["urlsafe_serial_number"],)))
        return super().get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["mdm"] = True
        ctx["form"] = self.form
        ctx["devices"] = self.devices
        ctx["devices_count"] = len(self.devices)
        bc = [(None, "MDM")]
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
        ctx = super().get_context_data(**kwargs)
        ctx["mdm"] = True
        ctx["machine"] = machine = MetaMachine.from_urlsafe_serial_number(kwargs["urlsafe_serial_number"])
        ctx["serial_number"] = machine.serial_number
        # enrolled devices
        ctx["enrolled_devices"] = (EnrolledDevice.objects.filter(serial_number=machine.serial_number)
                                                         .order_by("-updated_at"))
        ctx["enrolled_devices_count"] = ctx["enrolled_devices"].count()
        # dep device?
        try:
            ctx["dep_device"] = DEPDevice.objects.get(serial_number=machine.serial_number)
        except DEPDevice.DoesNotExist:
            pass
        # dep enrollment sessions
        ctx["dep_enrollment_sessions"] = DEPEnrollmentSession.objects.filter(
            enrollment_secret__serial_numbers__contains=[machine.serial_number]
        ).order_by("-updated_at")
        ctx["dep_enrollment_sessions_count"] = ctx["dep_enrollment_sessions"].count()
        # ota enrollment sessions
        ctx["ota_enrollment_sessions"] = OTAEnrollmentSession.objects.filter(
            enrollment_secret__serial_numbers__contains=[machine.serial_number]
        ).order_by("-updated_at")
        ctx["ota_enrollment_sessions_count"] = ctx["ota_enrollment_sessions"].count()
        return ctx


class PokeEnrolledDeviceView(LoginRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        enrolled_device = get_object_or_404(EnrolledDevice, pk=kwargs["pk"])
        send_enrolled_device_notification(enrolled_device)
        messages.info(request, "Device poked!")
        return HttpResponseRedirect(
            reverse("mdm:device",
                    args=(MetaMachine(enrolled_device.serial_number).get_urlsafe_serial_number(),))
        )


class EnrolledDeviceArtifactsView(LoginRequiredMixin, DetailView):
    model = EnrolledDevice
    template_name = "mdm/enrolled_device_artifacts.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["mdm"] = True
        context["urlsafe_serial_number"] = MetaMachine(self.object.serial_number).get_urlsafe_serial_number()
        context["installed_device_artifacts"] = sorted(self.object.installeddeviceartifact_set.all(),
                                                       key=lambda ida: ida.created_at, reverse=True)
        context["device_artifact_commands"] = sorted(self.object.deviceartifactcommand_set.all(),
                                                     key=lambda dac: dac.id, reverse=True)
        return context


class AssignDEPDeviceProfileView(LoginRequiredMixin, UpdateView):
    model = DEPDevice
    form_class = AssignDEPDeviceProfileForm

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["mdm"] = True
        return context

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


class RefreshDEPDeviceView(LoginRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        dep_device = get_object_or_404(DEPDevice, pk=kwargs["pk"])
        try:
            refresh_dep_device(dep_device)
        except DEPClientError as error:
            messages.error(request, str(error))
        else:
            messages.info(request, "DEP device refreshed")
        return HttpResponseRedirect("{}#dep_device".format(
            reverse("mdm:device",
                    args=(MetaMachine(dep_device.serial_number).get_urlsafe_serial_number(),))
        ))
