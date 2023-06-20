import io
import logging
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.contrib import messages
from django.core.exceptions import SuspiciousOperation
from django.db import transaction
from django.db.models import Count, Max
from django.http import FileResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse, reverse_lazy
from django.views.generic import CreateView, DeleteView, DetailView, FormView, ListView, TemplateView, UpdateView, View
from zentral.contrib.inventory.forms import EnrollmentSecretForm
from zentral.contrib.mdm.apns import send_enrolled_device_notification, send_enrolled_user_notification
from zentral.contrib.mdm.artifacts import update_blueprint_serialized_artifacts
from zentral.contrib.mdm.commands.base import load_command, registered_commands
from zentral.contrib.mdm.dep import add_dep_profile, assign_dep_device_profile, refresh_dep_device
from zentral.contrib.mdm.dep_client import DEPClient, DEPClientError
from zentral.contrib.mdm.forms import (ArtifactSearchForm, ArtifactVersionForm,
                                       AssignDEPDeviceEnrollmentForm, BlueprintArtifactForm,
                                       CreateDEPEnrollmentForm, UpdateDEPEnrollmentForm,
                                       CreateAssetArtifactForm,
                                       EnrolledDeviceSearchForm,
                                       OTAEnrollmentForm,
                                       SCEPConfigForm,
                                       UpdateArtifactForm,
                                       UserEnrollmentForm,
                                       UpgradeEnterpriseAppForm, UpgradeProfileForm, UpgradeStoreAppForm,
                                       UploadEnterpriseAppForm, UploadProfileForm)
from zentral.contrib.mdm.models import (Artifact, ArtifactVersion,
                                        Asset, Blueprint, BlueprintArtifact,
                                        Channel,
                                        DEPDevice, DEPEnrollment,
                                        DeviceCommand, UserCommand,
                                        EnrolledDevice, EnrolledUser, EnterpriseApp,
                                        OTAEnrollment,
                                        SCEPConfig,
                                        UserEnrollment,
                                        Profile, StoreApp)
from zentral.contrib.mdm.payloads import (build_configuration_profile_response,
                                          build_profile_service_configuration_profile)
from zentral.contrib.mdm.scep import SCEPChallengeType
from zentral.contrib.mdm.scep.microsoft_ca import MicrosoftCAChallengeForm
from zentral.contrib.mdm.scep.static import StaticChallengeForm
from zentral.contrib.mdm.skip_keys import skippable_setup_panes
from zentral.contrib.mdm.software_updates import iter_available_software_updates
from zentral.utils.views import CreateViewWithAudit, DeleteViewWithAudit, UpdateViewWithAudit


logger = logging.getLogger('zentral.contrib.mdm.views.management')


# All enrollments


class EnrollmentListView(LoginRequiredMixin, TemplateView):
    template_name = "mdm/enrollment_list.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        if self.request.user.has_perm("mdm.view_depenrollment"):
            ctx["dep_enrollments"] = list(DEPEnrollment.objects.all().order_by("-pk"))
        else:
            ctx["dep_enrollments"] = []
        if self.request.user.has_perm("mdm.view_otaenrollment"):
            ctx["ota_enrollments"] = list(OTAEnrollment.objects.all().order_by("-pk"))
        else:
            ctx["ota_enrollments"] = []
        if self.request.user.has_perm("mdm.view_userenrollment"):
            ctx["user_enrollments"] = list(UserEnrollment.objects.all().order_by("-pk"))
        else:
            ctx["user_enrollments"] = []
        return ctx


# DEP enrollments


class CreateDEPEnrollmentView(PermissionRequiredMixin, TemplateView):
    permission_required = "mdm.add_depenrollment"
    template_name = "mdm/depenrollment_form.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        dep_enrollment_form = kwargs.get("dep_enrollment_form")
        if not dep_enrollment_form:
            dep_enrollment_form = CreateDEPEnrollmentForm(prefix="de")
        context["dep_enrollment_form"] = dep_enrollment_form
        enrollment_secret_form = kwargs.get("enrollment_secret_form")
        if not enrollment_secret_form:
            enrollment_secret_form = EnrollmentSecretForm(
                prefix="es",
                no_restrictions=True,
            )
        context["enrollment_secret_form"] = enrollment_secret_form
        return context

    def post(self, request, *args, **kwargs):
        dep_enrollment_form = CreateDEPEnrollmentForm(request.POST, prefix="de")
        enrollment_secret_form = EnrollmentSecretForm(
            request.POST,
            prefix="es",
            no_restrictions=True,
        )
        if dep_enrollment_form.is_valid() and enrollment_secret_form.is_valid():
            dep_enrollment = dep_enrollment_form.save(commit=False)
            dep_enrollment.enrollment_secret = enrollment_secret_form.save()
            enrollment_secret_form.save_m2m()
            try:
                add_dep_profile(dep_enrollment)
            except DEPClientError as error:
                dep_enrollment_form.add_error(None, str(error))
            else:
                return redirect(dep_enrollment)
        return self.render_to_response(
            self.get_context_data(dep_enrollment_form=dep_enrollment_form,
                                  enrollment_secret_form=enrollment_secret_form)
        )


class DEPEnrollmentView(PermissionRequiredMixin, DetailView):
    permission_required = "mdm.view_depenrollment"
    model = DEPEnrollment

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        # TODO: pagination, separate view
        ctx["dep_enrollment_sessions"] = (ctx["object"].depenrollmentsession_set.all()
                                                       .select_related("enrollment_secret",
                                                                       "realm_user")
                                                       .order_by("-created_at"))
        ctx["dep_enrollment_sessions_count"] = ctx["dep_enrollment_sessions"].count()
        ctx["skip_keys"] = []
        for skey, content in skippable_setup_panes:
            for okey in self.object.skip_setup_items:
                if okey == skey:
                    ctx["skip_keys"].append(content)
        return ctx


class CheckDEPEnrollmentView(PermissionRequiredMixin, DetailView):
    permission_required = "mdm.view_depenrollment"
    model = DEPEnrollment
    template_name = "mdm/depenrollment_check.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        dep_client = DEPClient.from_dep_virtual_server(self.object.virtual_server)
        ctx["fetched_profile"] = dep_client.get_profile(self.object.uuid)
        return ctx


class UpdateDEPEnrollmentView(PermissionRequiredMixin, TemplateView):
    permission_required = "mdm.change_depenrollment"
    template_name = "mdm/depenrollment_form.html"

    def dispatch(self, request, *args, **kwargs):
        self.object = get_object_or_404(
            DEPEnrollment,
            pk=kwargs["pk"]
        )
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["object"] = self.object
        dep_enrollment_form = kwargs.get("dep_enrollment_form")
        if not dep_enrollment_form:
            dep_enrollment_form = UpdateDEPEnrollmentForm(prefix="de", instance=self.object)
        context["dep_enrollment_form"] = dep_enrollment_form
        enrollment_secret_form = kwargs.get("enrollment_secret_form")
        if not enrollment_secret_form:
            enrollment_secret_form = EnrollmentSecretForm(
                prefix="es",
                instance=self.object.enrollment_secret,
                no_restrictions=True,
            )
        context["enrollment_secret_form"] = enrollment_secret_form
        return context

    def post(self, request, *args, **kwargs):
        dep_enrollment_form = UpdateDEPEnrollmentForm(
            request.POST,
            prefix="de",
            instance=self.object
        )
        enrollment_secret_form = EnrollmentSecretForm(
            request.POST,
            prefix="es",
            instance=self.object.enrollment_secret,
            no_restrictions=True,
        )
        if dep_enrollment_form.is_valid() and enrollment_secret_form.is_valid():
            dep_enrollment = dep_enrollment_form.save(commit=False)
            dep_enrollment.enrollment_secret = enrollment_secret_form.save()
            enrollment_secret_form.save_m2m()
            try:
                add_dep_profile(dep_enrollment)
            except DEPClientError as error:
                dep_enrollment_form.add_error(None, str(error))
            else:
                return redirect(dep_enrollment)
        return self.render_to_response(
            self.get_context_data(dep_enrollment_form=dep_enrollment_form,
                                  enrollment_secret_form=enrollment_secret_form)
        )


# OTA Enrollments


class CreateOTAEnrollmentView(PermissionRequiredMixin, TemplateView):
    permission_required = "mdm.add_otaenrollment"
    template_name = "mdm/otaenrollment_form.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        ota_enrollment_form = kwargs.get("ota_enrollment_form")
        if not ota_enrollment_form:
            ota_enrollment_form = OTAEnrollmentForm(prefix="oe")
        context["ota_enrollment_form"] = ota_enrollment_form
        enrollment_secret_form = kwargs.get("enrollment_secret_form")
        if not enrollment_secret_form:
            enrollment_secret_form = EnrollmentSecretForm(
                prefix="es"
            )
        context["enrollment_secret_form"] = enrollment_secret_form
        return context

    def post(self, request, *args, **kwargs):
        ota_enrollment_form = OTAEnrollmentForm(request.POST, prefix="oe")
        enrollment_secret_form = EnrollmentSecretForm(
            request.POST,
            prefix="es"
        )
        if ota_enrollment_form.is_valid() and enrollment_secret_form.is_valid():
            ota_enrollment = ota_enrollment_form.save(commit=False)
            ota_enrollment.enrollment_secret = enrollment_secret_form.save()
            enrollment_secret_form.save_m2m()
            ota_enrollment.save()
            return redirect(ota_enrollment)
        else:
            return self.render_to_response(
                self.get_context_data(ota_enrollment_form=ota_enrollment_form,
                                      enrollment_secret_form=enrollment_secret_form)
            )


class OTAEnrollmentView(PermissionRequiredMixin, DetailView):
    permission_required = "mdm.view_otaenrollment"
    model = OTAEnrollment

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ota_enrollment = ctx["object"]
        ctx["meta_business_unit"] = ota_enrollment.enrollment_secret.meta_business_unit
        ctx["enroll_url"] = ota_enrollment.get_enroll_full_url()
        # TODO: pagination, separate view
        ctx["ota_enrollment_sessions"] = (ctx["object"].otaenrollmentsession_set.all()
                                                       .select_related("enrollment_secret",
                                                                       "realm_user")
                                                       .order_by("-created_at"))
        ctx["ota_enrollment_sessions_count"] = ctx["ota_enrollment_sessions"].count()
        return ctx


class DownloadProfileServicePayloadView(PermissionRequiredMixin, View):
    permission_required = "mdm.view_otaenrollment"

    def get(self, request, *args, **kwargs):
        ota_enrollment = get_object_or_404(
            OTAEnrollment,
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


class RevokeOTAEnrollmentView(PermissionRequiredMixin, TemplateView):
    permission_required = "mdm.change_otaenrollment"
    template_name = "mdm/revoke_ota_enrollment.html"

    def dispatch(self, request, *args, **kwargs):
        self.ota_enrollment = get_object_or_404(
            OTAEnrollment,
            pk=kwargs["pk"]
        )
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["ota_enrollment"] = self.ota_enrollment
        ctx["meta_business_unit"] = self.ota_enrollment.enrollment_secret.meta_business_unit
        return ctx

    def post(self, request, *args, **kwargs):
        self.ota_enrollment.revoke()
        return redirect(self.ota_enrollment)


class UpdateOTAEnrollmentView(PermissionRequiredMixin, TemplateView):
    permission_required = "mdm.change_otaenrollment"
    template_name = "mdm/otaenrollment_form.html"

    def dispatch(self, request, *args, **kwargs):
        self.ota_enrollment = get_object_or_404(
            OTAEnrollment,
            pk=kwargs["pk"]
        )
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["object"] = self.ota_enrollment
        ota_enrollment_form = kwargs.get("ota_enrollment_form")
        if not ota_enrollment_form:
            ota_enrollment_form = OTAEnrollmentForm(
                instance=self.ota_enrollment,
                prefix="oe"
            )
        context["ota_enrollment_form"] = ota_enrollment_form
        enrollment_secret_form = kwargs.get("enrollment_secret_form")
        if not enrollment_secret_form:
            enrollment_secret_form = EnrollmentSecretForm(
                instance=self.ota_enrollment.enrollment_secret,
                prefix="es"
            )
        context["enrollment_secret_form"] = enrollment_secret_form
        return context

    def post(self, request, *args, **kwargs):
        ota_enrollment_form = OTAEnrollmentForm(
            request.POST,
            instance=self.ota_enrollment,
            prefix="oe"
        )
        enrollment_secret_form = EnrollmentSecretForm(
            request.POST,
            instance=self.ota_enrollment.enrollment_secret,
            prefix="es"
        )
        if ota_enrollment_form.is_valid() and enrollment_secret_form.is_valid():
            ota_enrollment = ota_enrollment_form.save(commit=False)
            ota_enrollment.enrollment_secret = enrollment_secret_form.save()
            enrollment_secret_form.save_m2m()
            ota_enrollment.save()
            return redirect(ota_enrollment)
        else:
            return self.render_to_response(
                self.get_context_data(ota_enrollment_form=ota_enrollment_form,
                                      enrollment_secret_form=enrollment_secret_form)
            )


# User Enrollments


class CreateUserEnrollmentView(PermissionRequiredMixin, TemplateView):
    permission_required = "mdm.add_userenrollment"
    template_name = "mdm/userenrollment_form.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user_enrollment_form = kwargs.get("user_enrollment_form")
        if not user_enrollment_form:
            user_enrollment_form = UserEnrollmentForm(prefix="ue")
        context["user_enrollment_form"] = user_enrollment_form
        enrollment_secret_form = kwargs.get("enrollment_secret_form")
        if not enrollment_secret_form:
            enrollment_secret_form = EnrollmentSecretForm(
                prefix="es",
                no_serial_numbers=True,
                no_udids=True
            )
        context["enrollment_secret_form"] = enrollment_secret_form
        return context

    def post(self, request, *args, **kwargs):
        user_enrollment_form = UserEnrollmentForm(request.POST, prefix="ue")
        enrollment_secret_form = EnrollmentSecretForm(
            request.POST,
            prefix="es",
            no_serial_numbers=True,
            no_udids=True
        )
        if user_enrollment_form.is_valid() and enrollment_secret_form.is_valid():
            user_enrollment = user_enrollment_form.save(commit=False)
            user_enrollment.enrollment_secret = enrollment_secret_form.save()
            enrollment_secret_form.save_m2m()
            user_enrollment.save()
            return redirect(user_enrollment)
        else:
            return self.render_to_response(
                self.get_context_data(user_enrollment_form=user_enrollment_form,
                                      enrollment_secret_form=enrollment_secret_form)
            )


class UserEnrollmentView(PermissionRequiredMixin, DetailView):
    permission_required = "mdm.view_userenrollment"
    model = UserEnrollment

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        user_enrollment = ctx["object"]
        ctx["meta_business_unit"] = user_enrollment.enrollment_secret.meta_business_unit
        ctx["enroll_url"] = user_enrollment.get_enroll_full_url()
        ctx["service_discovery_url"] = user_enrollment.get_service_discovery_full_url()
        # TODO: pagination, separate view
        ctx["user_enrollment_sessions"] = (ctx["object"].userenrollmentsession_set.all()
                                                        .select_related("enrollment_secret")
                                                        .order_by("-created_at"))
        ctx["user_enrollment_sessions_count"] = ctx["user_enrollment_sessions"].count()
        return ctx


class RevokeUserEnrollmentView(PermissionRequiredMixin, TemplateView):
    permission_required = "mdm.change_userenrollment"
    template_name = "mdm/revoke_user_enrollment.html"

    def dispatch(self, request, *args, **kwargs):
        self.user_enrollment = get_object_or_404(
            UserEnrollment,
            pk=kwargs["pk"]
        )
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["user_enrollment"] = self.user_enrollment
        return ctx

    def post(self, request, *args, **kwargs):
        self.user_enrollment.revoke()
        return redirect(self.user_enrollment)


class UpdateUserEnrollmentView(PermissionRequiredMixin, TemplateView):
    permission_required = "mdm.change_userenrollment"
    template_name = "mdm/userenrollment_form.html"

    def dispatch(self, request, *args, **kwargs):
        self.user_enrollment = get_object_or_404(
            UserEnrollment,
            pk=kwargs["pk"]
        )
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["object"] = self.user_enrollment
        user_enrollment_form = kwargs.get("user_enrollment_form")
        if not user_enrollment_form:
            user_enrollment_form = UserEnrollmentForm(
                instance=self.user_enrollment,
                prefix="ue"
            )
        context["user_enrollment_form"] = user_enrollment_form
        enrollment_secret_form = kwargs.get("enrollment_secret_form")
        if not enrollment_secret_form:
            enrollment_secret_form = EnrollmentSecretForm(
                instance=self.user_enrollment.enrollment_secret,
                prefix="es",
                no_serial_numbers=True,
                no_udids=True
            )
        context["enrollment_secret_form"] = enrollment_secret_form
        return context

    def post(self, request, *args, **kwargs):
        user_enrollment_form = UserEnrollmentForm(
            request.POST,
            instance=self.user_enrollment,
            prefix="ue"
        )
        enrollment_secret_form = EnrollmentSecretForm(
            request.POST,
            instance=self.user_enrollment.enrollment_secret,
            prefix="es",
            no_serial_numbers=True,
            no_udids=True
        )
        if user_enrollment_form.is_valid() and enrollment_secret_form.is_valid():
            user_enrollment = user_enrollment_form.save(commit=False)
            user_enrollment.enrollment_secret = enrollment_secret_form.save()
            enrollment_secret_form.save_m2m()
            user_enrollment.save()
            return redirect(user_enrollment)
        else:
            return self.render_to_response(
                self.get_context_data(user_enrollment_form=user_enrollment_form,
                                      enrollment_secret_form=enrollment_secret_form)
            )


# Artifacts


class ArtifactListView(PermissionRequiredMixin, ListView):
    permission_required = "mdm.view_artifact"
    model = Artifact
    paginate_by = 30

    def get(self, request, *args, **kwargs):
        self.form = ArtifactSearchForm(self.request.GET)
        self.form.is_valid()
        redirect_to = self.form.get_redirect_to()
        if redirect_to:
            return redirect(redirect_to)
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        return self.form.get_queryset()

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["form"] = self.form
        page = ctx["page_obj"]
        if page.has_next():
            qd = self.request.GET.copy()
            qd['page'] = page.next_page_number()
            ctx['next_url'] = "?{}".format(qd.urlencode())
        if page.has_previous():
            qd = self.request.GET.copy()
            qd['page'] = page.previous_page_number()
            ctx['previous_url'] = "?{}".format(qd.urlencode())
        if page.number > 1:
            qd = self.request.GET.copy()
            qd.pop('page', None)
            ctx['reset_link'] = "?{}".format(qd.urlencode())
        return ctx


class BaseUploadArtifactView(PermissionRequiredMixin, FormView):
    permission_required = "mdm.add_artifact"

    def form_valid(self, form):
        self.artifact = form.save()
        messages.info(self.request, "Artifact created")
        return redirect(self.artifact)


class UploadEnterpriseAppView(BaseUploadArtifactView):
    form_class = UploadEnterpriseAppForm
    template_name = "mdm/enterpriseapp_form.html"


class UploadProfileView(BaseUploadArtifactView):
    form_class = UploadProfileForm
    template_name = "mdm/profile_form.html"


class ArtifactView(PermissionRequiredMixin, DetailView):
    permission_required = "mdm.view_artifact"
    model = Artifact

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        model_class = upgrade_view = None
        select_related_extra = ()
        if self.object.is_enterprise_app:
            model_class = EnterpriseApp
            upgrade_view = "upgrade_enterprise_app"
        elif self.object.is_profile:
            model_class = Profile
            upgrade_view = "upgrade_profile"
        elif self.object.is_store_app:
            model_class = StoreApp
            upgrade_view = "upgrade_store_app"
            select_related_extra = ("location_asset__asset", "location_asset__location")
        if model_class:
            ctx[f"{model_class._meta.model_name}_list"] = (
                model_class.objects.select_related("artifact_version", *select_related_extra)
                                   .filter(artifact_version__artifact=self.object)
                                   .order_by("-artifact_version__version")
            )
        if upgrade_view and self.request.user.has_perm("mdm.add_artifactversion"):
            ctx["upgrade_link"] = reverse(f"mdm:{upgrade_view}", args=(self.object.pk,))
        ctx["versions"] = (
            ArtifactVersion.objects.select_related("artifact", "enterprise_app", "profile", "store_app")
                                   .filter(artifact=self.object)
                                   .order_by("-version")
        )
        ctx["versions_count"] = ctx["versions"].count()
        ctx["blueprint_artifacts"] = (self.object.blueprintartifact_set.select_related("blueprint")
                                                                       .order_by("blueprint__name"))
        ctx["blueprint_artifacts_count"] = ctx["blueprint_artifacts"].count()
        return ctx


class UpdateArtifactView(PermissionRequiredMixin, UpdateView):
    permission_required = "mdm.change_artifact"
    model = Artifact
    form_class = UpdateArtifactForm


class DeleteArtifactView(PermissionRequiredMixin, DeleteView):
    permission_required = "mdm.delete_artifact"
    model = Artifact
    success_url = reverse_lazy("mdm:artifacts")

    def get_queryset(self):
        return Artifact.objects.can_be_deleted()


# Blueprint artifacts


class CreateBlueprintArtifactView(PermissionRequiredMixin, CreateView):
    permission_required = "mdm.add_blueprintartifact"
    model = BlueprintArtifact
    form_class = BlueprintArtifactForm

    def dispatch(self, request, *args, **kwargs):
        self.artifact = get_object_or_404(Artifact, pk=kwargs["pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["artifact"] = self.artifact
        return kwargs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["artifact"] = self.artifact
        return ctx

    def form_valid(self, form):
        response = super().form_valid(form)
        blueprint = self.object.blueprint
        update_blueprint_serialized_artifacts(blueprint)
        return response


class UpdateBlueprintArtifactView(PermissionRequiredMixin, UpdateView):
    permission_required = "mdm.change_blueprintartifact"
    model = BlueprintArtifact
    form_class = BlueprintArtifactForm

    def dispatch(self, request, *args, **kwargs):
        self.artifact = get_object_or_404(Artifact, pk=kwargs["artifact_pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_queryset(self):
        return super().get_queryset().filter(artifact=self.artifact)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["artifact"] = self.artifact
        return kwargs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["artifact"] = self.artifact
        return ctx


class DeleteBlueprintArtifactView(PermissionRequiredMixin, DeleteView):
    permission_required = "mdm.delete_blueprintartifact"
    model = BlueprintArtifact

    def dispatch(self, request, *args, **kwargs):
        self.artifact = get_object_or_404(Artifact, pk=kwargs["artifact_pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_queryset(self):
        return super().get_queryset().filter(artifact=self.artifact)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["artifact"] = self.artifact
        return ctx

    def get_success_url(self):
        return self.object.artifact.get_absolute_url()

    def form_valid(self, form):
        response = super().form_valid(form)
        update_blueprint_serialized_artifacts(self.object.blueprint)
        return response


# Artifact versions


class ArtifactVersionView(PermissionRequiredMixin, DetailView):
    permission_required = "mdm.view_artifactversion"
    model = ArtifactVersion

    def dispatch(self, request, *args, **kwargs):
        self.artifact = get_object_or_404(Artifact, pk=kwargs["artifact_pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_queryset(self):
        return super().get_queryset().filter(artifact=self.artifact)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["artifact"] = self.artifact
        if self.artifact.is_enterprise_app:
            ctx["enterprise_app"] = self.object.enterprise_app
        elif self.artifact.is_profile:
            ctx["profile"] = self.object.profile
        elif self.artifact.is_store_app:
            ctx["store_app"] = self.object.store_app
        return ctx


class UpdateArtifactVersionView(PermissionRequiredMixin, UpdateView):
    permission_required = "mdm.change_artifactversion"
    model = ArtifactVersion
    form_class = ArtifactVersionForm

    def dispatch(self, request, *args, **kwargs):
        self.artifact = get_object_or_404(Artifact, pk=kwargs["artifact_pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_queryset(self):
        return super().get_queryset().filter(artifact=self.artifact)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["artifact"] = self.artifact
        return kwargs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["artifact"] = self.artifact
        return ctx


class BaseUpgradeArtifactVersionView(PermissionRequiredMixin, TemplateView):
    permission_required = "mdm.add_artifactversion"
    template_name = "mdm/artifact_upgrade_form.html"

    def dispatch(self, request, *args, **kwargs):
        self.artifact = get_object_or_404(Artifact, pk=kwargs["pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_latest_artifact_version(self):
        return self.artifact.artifactversion_set.select_related(self.model).order_by("-version").first()

    def get_latest_object(self):
        latest_artifact_version = self.get_latest_artifact_version()
        if latest_artifact_version:
            return getattr(latest_artifact_version, self.model)

    def get_form_kwargs(self):
        kwargs = {}
        if self.request.method == "POST":
            kwargs.update({
                "data": self.request.POST,
                "files": self.request.FILES
            })
        return kwargs

    def get_object_form(self):
        return self.form(
            artifact=self.artifact,
            instance=self.get_latest_object(),
            **self.get_form_kwargs()
        )

    def get_version_form(self):
        return ArtifactVersionForm(
            artifact=self.artifact,
            instance=self.get_latest_artifact_version(),
            **self.get_form_kwargs()
        )

    def forms_valid(self, object_form, version_form):
        artifact_version = version_form.save(force_insert=True)
        object_form.save(artifact_version=artifact_version)
        for blueprint in self.artifact.blueprints():
            update_blueprint_serialized_artifacts(blueprint)
        return HttpResponseRedirect(artifact_version.get_absolute_url())

    def forms_invalid(self, object_form, version_form):
        return self.render_to_response(
            self.get_context_data(
                object_form=object_form,
                version_form=version_form
            )
        )

    def get_context_data(self, **kwargs):
        kwargs["model_display"] = self.model_display
        kwargs["artifact"] = self.artifact
        kwargs["latest_object"] = self.get_latest_object()
        if "object_form" not in kwargs:
            kwargs["object_form"] = self.get_object_form()
        if "version_form" not in kwargs:
            kwargs["version_form"] = self.get_version_form()
        return super().get_context_data(**kwargs)

    def post(self, request, *args, **kwargs):
        object_form = self.get_object_form()
        version_form = self.get_version_form()
        if object_form.is_valid() and version_form.is_valid():
            return self.forms_valid(object_form, version_form)
        else:
            return self.forms_invalid(object_form, version_form)


class UpgradeEnterpriseAppView(BaseUpgradeArtifactVersionView):
    form = UpgradeEnterpriseAppForm
    model = "enterprise_app"
    model_display = "Enterprise app"


class UpgradeProfileView(BaseUpgradeArtifactVersionView):
    form = UpgradeProfileForm
    model = "profile"
    model_display = "Profile"


class UpgradeStoreAppView(BaseUpgradeArtifactVersionView):
    form = UpgradeStoreAppForm
    model = "store_app"
    model_display = "Store app"


class DeleteArtifactVersionView(PermissionRequiredMixin, DeleteView):
    permission_required = "mdm.delete_artifactversion"
    model = ArtifactVersion

    def dispatch(self, request, *args, **kwargs):
        self.artifact = get_object_or_404(Artifact, pk=kwargs["artifact_pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_queryset(self):
        return ArtifactVersion.objects.can_be_deleted().filter(artifact=self.artifact)

    def get_success_url(self):
        return self.artifact.get_absolute_url()

    def form_valid(self, form):
        response = super().form_valid(form)
        for blueprint in self.object.artifact.blueprints():
            update_blueprint_serialized_artifacts(blueprint)
        return response


class DownloadProfileView(PermissionRequiredMixin, View):
    permission_required = "mdm.view_artifact"

    def get(self, request, **kwargs):
        profile = get_object_or_404(Profile, artifact_version__pk=kwargs["artifact_version_pk"])
        return FileResponse(
            io.BytesIO(profile.source),
            content_type="application/x-plist",
            as_attachment=True,
            filename=profile.filename or f"profile_{profile.artifact_version.pk}.mobileconfig"
        )


# Assets


class AssetListView(PermissionRequiredMixin, ListView):
    permission_required = "mdm.view_asset"
    model = Asset


class AssetView(PermissionRequiredMixin, DetailView):
    permission_required = "mdm.view_asset"
    model = Asset

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["location_assets"] = list(
            self.object.locationasset_set.select_related("location")
                                         .order_by("location__name")
        )
        ctx["artifacts"] = self.object.get_artifacts_store_apps()
        return ctx


class CreateAssetArtifactView(PermissionRequiredMixin, FormView):
    permission_required = ("mdm.view_asset", "mdm.add_artifact")
    template_name = "mdm/assetartifact_form.html"
    form_class = CreateAssetArtifactForm

    def dispatch(self, request, *args, **kwargs):
        self.asset = get_object_or_404(Asset, pk=kwargs["pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["asset"] = self.asset
        return ctx

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["asset"] = self.asset
        return kwargs

    def form_valid(self, form):
        store_app = form.save()
        messages.info(self.request, "Artifact created")
        return redirect(store_app.artifact_version.artifact)


# Blueprints


class BlueprintListView(PermissionRequiredMixin, ListView):
    permission_required = "mdm.view_blueprint"
    model = Blueprint

    def get_queryset(self):
        return (super().get_queryset().annotate(Count("blueprintartifact", distinct=True),
                                                Count("depenrollment", distinct=True),
                                                Count("otaenrollment", distinct=True),
                                                Count("userenrollment", distinct=True))
                                      .order_by("name"))


class CreateBlueprintView(PermissionRequiredMixin, CreateViewWithAudit):
    permission_required = "mdm.add_blueprint"
    model = Blueprint
    fields = ("name",
              "inventory_interval",
              "collect_apps",
              "collect_certificates",
              "collect_profiles")

    def form_valid(self, form):
        response = super().form_valid(form)
        update_blueprint_serialized_artifacts(self.object)
        return response


class BlueprintView(PermissionRequiredMixin, DetailView):
    permission_required = "mdm.view_blueprint"
    model = Blueprint

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["artifacts"] = (self.object.blueprintartifact_set.select_related("artifact")
                                                             .annotate(Max("artifact__artifactversion__version"))
                                                             .order_by("artifact__name"))
        ctx["artifacts_count"] = ctx["artifacts"].count()
        for enrollment_type in ("dep", "ota", "user"):
            ctx[f"{enrollment_type}_enrollments"] = list(
                getattr(self.object, f"{enrollment_type}enrollment_set").order_by("name").all()
            )
        return ctx


class UpdateBlueprintView(PermissionRequiredMixin, UpdateViewWithAudit):
    permission_required = "mdm.change_blueprint"
    model = Blueprint
    fields = ("name",
              "inventory_interval",
              "collect_apps",
              "collect_certificates",
              "collect_profiles")

    def form_valid(self, form):
        response = super().form_valid(form)
        update_blueprint_serialized_artifacts(self.object)
        return response


class DeleteBlueprintView(PermissionRequiredMixin, DeleteViewWithAudit):
    permission_required = "mdm.delete_blueprint"
    queryset = Blueprint.objects.can_be_deleted()
    success_url = reverse_lazy("mdm:blueprints")


# SCEP Configurations


class SCEPConfigListView(PermissionRequiredMixin, ListView):
    permission_required = "mdm.view_scepconfig"
    model = SCEPConfig
    paginate_by = 20


class CreateSCEPConfigView(PermissionRequiredMixin, TemplateView):
    template_name = "mdm/scepconfig_form.html"
    permission_required = "mdm.add_scepconfig"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        scep_config_form = kwargs.get("scep_config_form")
        if not scep_config_form:
            scep_config_form = SCEPConfigForm(prefix="sc")
        context["scep_config_form"] = scep_config_form
        microsoft_ca_form = kwargs.get("microsoft_ca_form")
        if not microsoft_ca_form:
            microsoft_ca_form = MicrosoftCAChallengeForm(prefix="mc")
        context["microsoft_ca_form"] = microsoft_ca_form
        static_form = kwargs.get("static_form")
        if not static_form:
            static_form = StaticChallengeForm(prefix="s")
        context["static_form"] = static_form
        return context

    def post(self, request, *args, **kwargs):
        scep_config_form = SCEPConfigForm(request.POST, prefix="sc")
        microsoft_ca_form = MicrosoftCAChallengeForm(request.POST, prefix="mc")
        static_form = StaticChallengeForm(request.POST, prefix="s")
        if scep_config_form.is_valid():
            challenge_type = SCEPChallengeType[scep_config_form.cleaned_data["challenge_type"]]
            if challenge_type == SCEPChallengeType.MICROSOFT_CA:
                challenge_form = microsoft_ca_form
            elif challenge_type == SCEPChallengeType.STATIC:
                challenge_form = static_form
            if challenge_form.is_valid():
                scep_config = scep_config_form.save(commit=False)
                scep_config.set_challenge_kwargs(challenge_form.cleaned_data)
                scep_config.save()
                return redirect(scep_config)
        else:
            return self.render_to_response(
                self.get_context_data(scep_config_form=scep_config_form,
                                      microsoft_ca_form=microsoft_ca_form,
                                      static_form=static_form)
            )


class SCEPConfigView(PermissionRequiredMixin, DetailView):
    permission_required = "mdm.view_scepconfig"
    model = SCEPConfig


class UpdateSCEPConfigView(PermissionRequiredMixin, TemplateView):
    template_name = "mdm/scepconfig_form.html"
    permission_required = "mdm.change_scepconfig"

    def dispatch(self, request, *args, **kwargs):
        self.scep_config = get_object_or_404(SCEPConfig, pk=kwargs["pk"])
        self.challenge_type = SCEPChallengeType[self.scep_config.challenge_type]
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["object"] = self.scep_config
        scep_config_form = kwargs.get("scep_config_form")
        if not scep_config_form:
            scep_config_form = SCEPConfigForm(
                instance=self.scep_config,
                prefix="sc"
            )
        context["scep_config_form"] = scep_config_form
        microsoft_ca_form = kwargs.get("microsoft_ca_form")
        if not microsoft_ca_form:
            microsoft_ca_form = MicrosoftCAChallengeForm(
                prefix="mc",
                initial=(
                    self.scep_config.get_challenge_kwargs()
                    if self.challenge_type == SCEPChallengeType.MICROSOFT_CA
                    else None
                )
            )
        context["microsoft_ca_form"] = microsoft_ca_form
        static_form = kwargs.get("static_form")
        if not static_form:
            static_form = StaticChallengeForm(
                prefix="s",
                initial=(
                    self.scep_config.get_challenge_kwargs()
                    if self.challenge_type == SCEPChallengeType.STATIC
                    else None
                )
            )
        context["static_form"] = static_form
        return context

    def post(self, request, *args, **kwargs):
        scep_config_form = SCEPConfigForm(
            request.POST,
            instance=self.scep_config,
            prefix="sc"
        )
        microsoft_ca_form = MicrosoftCAChallengeForm(
            request.POST,
            prefix="mc",
            initial=(
                self.scep_config.get_challenge_kwargs()
                if self.challenge_type == SCEPChallengeType.MICROSOFT_CA
                else None
            )
        )
        static_form = StaticChallengeForm(
            request.POST,
            prefix="s",
            initial=(
                self.scep_config.get_challenge_kwargs()
                if self.challenge_type == SCEPChallengeType.STATIC
                else None
            )
        )
        if scep_config_form.is_valid():
            challenge_type = SCEPChallengeType[scep_config_form.cleaned_data["challenge_type"]]
            if challenge_type == SCEPChallengeType.MICROSOFT_CA:
                challenge_form = microsoft_ca_form
            elif challenge_type == SCEPChallengeType.STATIC:
                challenge_form = static_form
            if challenge_form.is_valid():
                scep_config = scep_config_form.save(commit=False)
                scep_config.set_challenge_kwargs(challenge_form.cleaned_data)
                scep_config.save()
                return redirect(scep_config)
        else:
            return self.render_to_response(
                self.get_context_data(scep_config_form=scep_config_form,
                                      microsoft_ca_form=microsoft_ca_form,
                                      static_form=static_form)
            )


class DeleteSCEPConfigView(PermissionRequiredMixin, DeleteView):
    permission_required = "mdm.delete_scepconfig"
    model = SCEPConfig
    success_url = reverse_lazy("mdm:scep_configs")

    def get_object(self, queryset=None):
        obj = super().get_object(queryset)
        if not obj.can_be_deleted():
            raise SuspiciousOperation("This SCEP config cannot be deleted")
        return obj


# Devices


class EnrolledDeviceListView(PermissionRequiredMixin, ListView):
    permission_required = "mdm.view_enrolleddevice"
    model = EnrolledDevice
    paginate_by = 20

    def get(self, request, *args, **kwargs):
        self.form = EnrolledDeviceSearchForm(request.GET)
        self.form.is_valid()
        redirect_to = self.form.get_redirect_to()
        if redirect_to:
            return redirect(redirect_to)
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        return self.form.get_queryset()

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["form"] = self.form
        bc = [(reverse("mdm:index"), "MDM")]
        page = ctx["page_obj"]
        reset_link = None
        if page.has_next():
            qd = self.request.GET.copy()
            qd['page'] = page.next_page_number()
            ctx['next_url'] = "?{}".format(qd.urlencode())
        if page.has_previous():
            qd = self.request.GET.copy()
            qd['page'] = page.previous_page_number()
            ctx['previous_url'] = "?{}".format(qd.urlencode())
        if page.number > 1:
            qd = self.request.GET.copy()
            qd.pop('page', None)
            reset_link = "?{}".format(qd.urlencode())
        if self.form.has_changed():
            bc.extend([(reverse("mdm:enrolled_devices"), "Devices"),
                       (reset_link, "Search")])
        else:
            bc.extend([(reset_link, "Devices")])
        ctx["breadcrumbs"] = bc
        return ctx


class EnrolledDeviceView(PermissionRequiredMixin, DetailView):
    permission_required = "mdm.view_enrolleddevice"
    model = EnrolledDevice
    max_command_number = 10

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["available_software_updates"] = list(iter_available_software_updates(self.object))
        try:
            ctx["dep_device"] = (DEPDevice.objects.select_related("virtual_server", "enrollment")
                                                  .get(serial_number=self.object.serial_number))
        except DEPDevice.DoesNotExist:
            pass
        ctx["target_artifacts"] = (self.object.target_artifacts
                                              .select_related("artifact_version__artifact")
                                              .all()
                                              .order_by("-updated_at"))
        ctx["target_artifacts_count"] = ctx["target_artifacts"].count()
        commands_qs = (
            self.object.commands
                       .select_related("artifact_version__artifact")
                       .all()
                       .order_by("-created_at")
        )
        ctx["loaded_commands"] = [
            load_command(cmd)
            for cmd in commands_qs[:self.max_command_number]
        ]
        ctx["commands_count"] = commands_qs.count()
        ctx["enrollment_session_info_list"] = list(self.object.iter_enrollment_session_info())
        ctx["enrollment_session_info_count"] = len(ctx["enrollment_session_info_list"])
        return ctx


class EnrolledDeviceCommandsView(PermissionRequiredMixin, ListView):
    permission_required = "mdm.view_enrolleddevice"
    model = DeviceCommand
    paginate_by = 50

    def get(self, request, *args, **kwargs):
        self.enrolled_device = get_object_or_404(EnrolledDevice, pk=kwargs["pk"])
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        return (
            self.enrolled_device.commands
                                .select_related("artifact_version__artifact")
                                .all()
                                .order_by("-created_at")
        )

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["enrolled_device"] = self.enrolled_device
        page = ctx["page_obj"]
        ctx["loaded_commands"] = (load_command(cmd) for cmd in page)
        if page.has_next():
            qd = self.request.GET.copy()
            qd['page'] = page.next_page_number()
            ctx['next_url'] = "?{}".format(qd.urlencode())
        if page.has_previous():
            qd = self.request.GET.copy()
            qd['page'] = page.previous_page_number()
            ctx['previous_url'] = "?{}".format(qd.urlencode())
        if page.number > 1:
            qd = self.request.GET.copy()
            qd.pop('page', None)
            ctx['reset_link'] = "?{}".format(qd.urlencode())
        return ctx


class PokeEnrolledDeviceView(PermissionRequiredMixin, View):
    permission_required = "mdm.change_enrolleddevice"

    def post(self, request, *args, **kwargs):
        enrolled_device = get_object_or_404(EnrolledDevice, pk=kwargs["pk"])
        send_enrolled_device_notification(enrolled_device)
        messages.info(request, "Device poked!")
        return redirect(enrolled_device)


class ChangeEnrolledDeviceBlueprintView(PermissionRequiredMixin, UpdateView):
    permission_required = "mdm.change_enrolleddevice"
    model = EnrolledDevice
    fields = ("blueprint",)

    def form_valid(self, form):
        old_blueprint = EnrolledDevice.objects.get(pk=self.object.pk).blueprint
        if self.object.blueprint != old_blueprint:
            transaction.on_commit(lambda: send_enrolled_device_notification(self.object))
        return super().form_valid(form)


class BlockEnrolledDeviceView(PermissionRequiredMixin, DetailView):
    permission_required = "mdm.change_enrolleddevice"
    model = EnrolledDevice
    template_name = "mdm/enrolleddevice_confirm_block.html"

    def get_queryset(self):
        return EnrolledDevice.objects.allowed()

    def post(self, request, *args, **kwargs):
        enrolled_device = self.get_object()
        enrolled_device.block()
        transaction.on_commit(lambda: send_enrolled_device_notification(enrolled_device))
        return redirect(enrolled_device)


class UnblockEnrolledDeviceView(PermissionRequiredMixin, DetailView):
    permission_required = "mdm.change_enrolleddevice"
    model = EnrolledDevice
    template_name = "mdm/enrolleddevice_confirm_unblock.html"

    def get_queryset(self):
        return EnrolledDevice.objects.blocked()

    def post(self, request, *args, **kwargs):
        enrolled_device = self.get_object()
        enrolled_device.unblock()
        return redirect(enrolled_device)


class EnrolledUserView(PermissionRequiredMixin, DetailView):
    permission_required = "mdm.view_enrolleduser"
    model = EnrolledUser
    max_command_number = 10

    def get_queryset(self):
        return (super().get_queryset().select_related("enrolled_device")
                                      .filter(enrolled_device__pk=self.kwargs["device_pk"]))

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["enrolled_device"] = ctx["object"].enrolled_device
        ctx["target_artifacts"] = (self.object.target_artifacts
                                              .select_related("artifact_version__artifact")
                                              .all()
                                              .order_by("-updated_at"))
        ctx["target_artifacts_count"] = ctx["target_artifacts"].count()
        commands_qs = (
            self.object.commands
                       .select_related("artifact_version__artifact")
                       .all()
                       .order_by("-created_at")
        )
        ctx["loaded_commands"] = [
            load_command(cmd)
            for cmd in commands_qs[:self.max_command_number]
        ]
        ctx["commands_count"] = commands_qs.count()
        return ctx


class EnrolledUserCommandsView(PermissionRequiredMixin, ListView):
    permission_required = "mdm.view_enrolleduser"
    model = UserCommand
    paginate_by = 50

    def get(self, request, *args, **kwargs):
        self.enrolled_user = get_object_or_404(
            EnrolledUser.objects.select_related("enrolled_device"),
            enrolled_device__pk=kwargs["device_pk"],
            pk=kwargs["pk"]
        )
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        return (
            self.enrolled_user.commands
                              .select_related("artifact_version__artifact")
                              .all()
                              .order_by("-created_at")
        )

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["enrolled_user"] = self.enrolled_user
        ctx["enrolled_device"] = self.enrolled_user.enrolled_device
        page = ctx["page_obj"]
        ctx["loaded_commands"] = (load_command(cmd) for cmd in page)
        if page.has_next():
            qd = self.request.GET.copy()
            qd['page'] = page.next_page_number()
            ctx['next_url'] = "?{}".format(qd.urlencode())
        if page.has_previous():
            qd = self.request.GET.copy()
            qd['page'] = page.previous_page_number()
            ctx['previous_url'] = "?{}".format(qd.urlencode())
        if page.number > 1:
            qd = self.request.GET.copy()
            qd.pop('page', None)
            ctx['reset_link'] = "?{}".format(qd.urlencode())
        return ctx


class PokeEnrolledUserView(PermissionRequiredMixin, View):
    permission_required = "mdm.change_enrolleduser"

    def post(self, request, *args, **kwargs):
        enrolled_user = get_object_or_404(
            EnrolledUser.objects.select_related("enrolled_device__push_certificate"),
            pk=kwargs["pk"]
        )
        send_enrolled_user_notification(enrolled_user)
        messages.info(request, "User poked!")
        return redirect(enrolled_user)


class CreateEnrolledDeviceCommandView(PermissionRequiredMixin, FormView):
    permission_required = "mdm.add_devicecommand"
    command_name = None
    template_name = "mdm/enrolleddevice_create_command.html"

    def dispatch(self, request, *args, **kwargs):
        self.enrolled_device = get_object_or_404(
            EnrolledDevice,
            pk=kwargs["pk"]
        )
        try:
            self.command_class = registered_commands[self.command_name]
        except KeyError:
            # should not happen
            raise SuspiciousOperation("Unknown command model class: %s", self.command_name)
        return super().dispatch(request, *args, **kwargs)

    def get_form_class(self):
        return self.command_class.form_class

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["channel"] = Channel.DEVICE
        kwargs["enrolled_device"] = self.enrolled_device
        return kwargs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["command_class_display"] = self.command_class.get_display_name().lower()
        ctx["enrolled_device"] = self.enrolled_device
        return ctx

    def form_valid(self, form):
        self.command_class.create_for_device(
            self.enrolled_device,
            kwargs=form.get_command_kwargs(),
            queue=True,
        )
        messages.info(self.request, f"{self.command_class.get_display_name()} command successfully created")
        return redirect(self.enrolled_device)


class DownloadEnrolledDeviceCommandResultView(PermissionRequiredMixin, View):
    permission_required = "mdm.view_devicecommand"

    def get(self, request, *args, **kwargs):
        command = get_object_or_404(DeviceCommand, uuid=kwargs["uuid"], result__isnull=False)
        return FileResponse(
            io.BytesIO(command.result),
            content_type="application/x-plist",
            as_attachment=True,
            filename=f"device_command_{command.uuid}-result.plist"
        )


class DownloadEnrolledUserCommandResultView(PermissionRequiredMixin, View):
    permission_required = "mdm.view_usercommand"

    def get(self, request, *args, **kwargs):
        command = get_object_or_404(UserCommand, uuid=kwargs["uuid"], result__isnull=False)
        return FileResponse(
            io.BytesIO(command.result),
            content_type="application/x-plist",
            as_attachment=True,
            filename=f"user_command_{command.uuid}-result.plist"
        )


# DEP device


class AssignDEPDeviceProfileView(PermissionRequiredMixin, UpdateView):
    permission_required = "mdm.change_depdevice"
    model = DEPDevice
    form_class = AssignDEPDeviceEnrollmentForm

    def form_valid(self, form):
        dep_device = form.save(commit=False)
        try:
            assign_dep_device_profile(dep_device, dep_device.enrollment)
        except DEPClientError as e:
            form.add_error(None, str(e))
            return self.form_invalid(form)
        else:
            messages.info(self.request, "Profile {} successfully assigned to device {}.".format(
                dep_device.enrollment, dep_device.serial_number
            ))
            return redirect(dep_device)


class RefreshDEPDeviceView(PermissionRequiredMixin, View):
    permission_required = "mdm.change_depdevice"

    def post(self, request, *args, **kwargs):
        dep_device = get_object_or_404(DEPDevice, pk=kwargs["pk"])
        try:
            refresh_dep_device(dep_device)
        except DEPClientError as error:
            messages.error(request, str(error))
        else:
            messages.info(request, "DEP device refreshed")
        return redirect(dep_device)
