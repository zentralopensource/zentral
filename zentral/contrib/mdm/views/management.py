import io
import logging
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.contrib import messages
from django.core.exceptions import SuspiciousOperation
from django.core.files.uploadhandler import TemporaryFileUploadHandler
from django.db import transaction
from django.db.models import Count, Max
from django.http import FileResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse, reverse_lazy
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.views.generic import CreateView, DeleteView, DetailView, FormView, ListView, TemplateView, UpdateView, View
from realms.models import RealmUser
from zentral.contrib.inventory.forms import EnrollmentSecretForm
from zentral.contrib.mdm.commands.custom import CustomCommand, CustomCommandForm
from zentral.contrib.mdm.declarations import update_blueprint_activation, update_blueprint_declaration_items
from zentral.contrib.mdm.dep import add_dep_profile, assign_dep_device_profile, refresh_dep_device
from zentral.contrib.mdm.dep_client import DEPClient, DEPClientError
from zentral.contrib.mdm.forms import (AssignDEPDeviceEnrollmentForm, BlueprintArtifactForm,
                                       CreateDEPEnrollmentForm, UpdateDEPEnrollmentForm,
                                       EnrolledDeviceSearchForm,
                                       OTAEnrollmentForm,
                                       SCEPConfigForm,
                                       UpdateArtifactForm,
                                       UserEnrollmentForm, UserEnrollmentEnrollForm,
                                       UploadEnterpriseAppForm, UploadProfileForm,
                                       CreateAssetArtifactForm)
from zentral.contrib.mdm.models import (Artifact, ArtifactType, Asset, Blueprint, BlueprintArtifact,
                                        DEPDevice, DEPEnrollment,
                                        DeviceCommand,
                                        EnrolledDevice, EnrolledUser, EnterpriseApp,
                                        OTAEnrollment, OTAEnrollmentSession,
                                        SCEPConfig,
                                        UserEnrollment, UserEnrollmentSession,
                                        Profile, StoreApp)
from zentral.contrib.mdm.payloads import (build_configuration_profile_response,
                                          build_mdm_configuration_profile,
                                          build_profile_service_configuration_profile)
from zentral.contrib.mdm.scep import SCEPChallengeType
from zentral.contrib.mdm.scep.microsoft_ca import MicrosoftCAChallengeForm
from zentral.contrib.mdm.scep.static import StaticChallengeForm
from zentral.contrib.mdm.apns import send_enrolled_device_notification, send_enrolled_user_notification


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


def ota_enroll_callback(request, realm_authentication_session, ota_enrollment_pk):
    """
    Realm authorization session callback used to start authenticated OTAEnrollmentSession
    """
    ota_enrollment = OTAEnrollment.objects.get(pk=ota_enrollment_pk, realm__isnull=False)
    realm_user = realm_authentication_session.user
    request.session["_ota_{}_realm_user_pk".format(ota_enrollment.pk)] = str(realm_user.pk)
    return reverse("mdm:ota_enrollment_enroll", args=(ota_enrollment.pk,))


class OTAEnrollmentEnrollView(View):
    def get(self, request, *args, **kwargs):
        ota_enrollment = get_object_or_404(
            OTAEnrollment,
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
                ota_enrollment.realm.backend_instance.initialize_session(request, callback, **callback_kwargs)
            )
        else:
            ota_enrollment_session = OTAEnrollmentSession.objects.create_from_realm_user(ota_enrollment, realm_user)
            # start OTAEnrollmentSession, build config profile, return config profile
            return build_configuration_profile_response(
                build_profile_service_configuration_profile(ota_enrollment_session),
                "zentral_profile_service"
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


class UserEnrollmentEnrollView(FormView):
    form_class = UserEnrollmentEnrollForm
    template_name = "mdm/user_enrollment_enroll.html"

    def dispatch(self, request, *args, **kwargs):
        self.user_enrollment = get_object_or_404(
            UserEnrollment,
            pk=kwargs["pk"]
        )
        if not self.user_enrollment.enrollment_secret.is_valid():
            # should not happen
            raise SuspiciousOperation
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["user_enrollment"] = self.user_enrollment
        return ctx

    def form_valid(self, form):
        managed_apple_id = form.cleaned_data["managed_apple_id"]
        user_enrollment_session = UserEnrollmentSession.objects.create_from_user_enrollment(
            self.user_enrollment, managed_apple_id
        )
        return build_configuration_profile_response(
            build_mdm_configuration_profile(user_enrollment_session),
            "zentral_user_enrollment"
        )


# Artifacts


class ArtifactListView(PermissionRequiredMixin, ListView):
    permission_required = "mdm.view_artifact"
    model = Artifact

    def get_queryset(self):
        return super().get_queryset().filter(trashed_at__isnull=True).annotate(Count("blueprintartifact"))


class BaseUploadArtifactView(PermissionRequiredMixin, FormView):
    permission_required = "mdm.add_artifact"
    form_class = None
    template_name = None

    def form_valid(self, form):
        self.artifact, operation = form.save()
        if operation:
            messages.info(self.request, f"Artifact {operation}")
        else:
            messages.warning(self.request, "Artifact already exists")
        return redirect(self.artifact)


@method_decorator(csrf_protect, 'post')
class UploadEnterpriseAppView(BaseUploadArtifactView):
    form_class = UploadEnterpriseAppForm
    template_name = "mdm/enterpriseapp_form.html"

    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        # for temporary file, for xar.
        # see https://docs.djangoproject.com/en/3.1/topics/http/file-uploads/#modifying-upload-handlers-on-the-fly
        request.upload_handlers = [TemporaryFileUploadHandler(request)]
        return super().dispatch(request, *args, **kwargs)


class UploadProfileView(BaseUploadArtifactView):
    form_class = UploadProfileForm
    template_name = "mdm/profile_form.html"


class ArtifactView(PermissionRequiredMixin, DetailView):
    permission_required = "mdm.view_artifact"
    model = Artifact

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        model_class = None
        if self.object.type == ArtifactType.Profile.name:
            model_class = Profile
        elif self.object.type == ArtifactType.EnterpriseApp.name:
            model_class = EnterpriseApp
        elif self.object.type == ArtifactType.StoreApp.name:
            model_class = StoreApp
        if model_class:
            ctx[f"{model_class._meta.model_name}_list"] = qs = (
                model_class.objects.select_related("artifact_version")
                                   .filter(artifact_version__artifact=self.object)
                                   .order_by("-artifact_version__version")
            )
            ctx["versions_count"] = qs.count()
        ctx["blueprint_artifacts"] = (self.object.blueprintartifact_set.select_related("blueprint")
                                                                       .order_by("blueprint__name"))
        ctx["blueprint_artifacts_count"] = ctx["blueprint_artifacts"].count()
        return ctx


class UpdateArtifactView(PermissionRequiredMixin, UpdateView):
    permission_required = "mdm.change_artifact"
    model = Artifact
    form_class = UpdateArtifactForm

    def get_queryset(self):
        return super().get_queryset().exclude(type=ArtifactType.EnterpriseApp.name)


class TrashArtifactView(PermissionRequiredMixin, DeleteView):
    permission_required = "mdm.delete_artifact"
    model = Artifact

    def delete(self, request, *args, **kwargs):
        self.object = self.get_object()
        try:
            self.object.delete()
        except Exception:
            # TODO verify
            self.object.trashed_at = timezone.now()
            self.object.save()
        return redirect("mdm:artifacts")


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
        update_blueprint_activation(blueprint, commit=False)
        update_blueprint_declaration_items(blueprint, commit=True)
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

    def delete(self, request, *args, **kwargs):
        self.object = self.get_object()
        blueprint = self.object.blueprint
        self.object.delete()
        update_blueprint_activation(blueprint, commit=False)
        update_blueprint_declaration_items(blueprint, commit=True)
        return redirect(self.artifact)


# Assets


class AssetListView(PermissionRequiredMixin, ListView):
    permission_required = "mdm.view_asset"
    model = Asset


class AssetView(PermissionRequiredMixin, DetailView):
    permission_required = "mdm.view_asset"
    model = Asset

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["server_token_assets"] = list(
            self.object.servertokenasset_set.select_related("server_token")
                                            .order_by("server_token__location_name")
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
        return redirect(store_app)


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


class CreateBlueprintView(PermissionRequiredMixin, CreateView):
    permission_required = "mdm.add_blueprint"
    model = Blueprint
    fields = ("name",
              "inventory_interval",
              "collect_apps",
              "collect_certificates",
              "collect_profiles")


class BlueprintView(PermissionRequiredMixin, DetailView):
    permission_required = "mdm.view_blueprint"
    model = Blueprint

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["artifacts"] = (self.object.blueprintartifact_set.select_related("artifact")
                                                             .annotate(Max("artifact__artifactversion__version"))
                                                             .order_by(
                                                                 "-install_before_setup_assistant",
                                                                 "-priority", "artifact__name"))
        ctx["artifacts_count"] = ctx["artifacts"].count()
        for enrollment_type in ("dep", "ota", "user"):
            ctx[f"{enrollment_type}_enrollments"] = list(
                getattr(self.object, f"{enrollment_type}enrollment_set").order_by("name").all()
            )
        return ctx


class UpdateBlueprintView(PermissionRequiredMixin, UpdateView):
    permission_required = "mdm.change_blueprint"
    model = Blueprint
    fields = ("name",
              "inventory_interval",
              "collect_apps",
              "collect_certificates",
              "collect_profiles")


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

    def dispatch(self, request, *args, **kwargs):
        self.form = EnrolledDeviceSearchForm(request.GET)
        self.form.is_valid()
        return super().dispatch(request, *args, **kwargs)

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
        try:
            ctx["dep_device"] = (DEPDevice.objects.select_related("virtual_server", "enrollment")
                                                  .get(serial_number=self.object.serial_number))
        except DEPDevice.DoesNotExist:
            pass
        ctx["installed_artifacts"] = (self.object.installed_artifacts
                                                 .select_related("artifact_version__artifact")
                                                 .all()
                                                 .order_by("-updated_at"))
        ctx["installed_artifacts_count"] = ctx["installed_artifacts"].count()
        commands_qs = (
            self.object.commands
                       .select_related("artifact_version__artifact")
                       .all()
                       .order_by("-created_at")
        )
        ctx["commands"] = commands_qs[:self.max_command_number]
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
            transaction.on_commit(lambda: send_enrolled_device_notification(
                self.object, notify_users=True
            ))
        return super().form_valid(form)


class EnrolledUserView(PermissionRequiredMixin, DetailView):
    permission_required = "mdm.view_enrolleduser"
    model = EnrolledUser

    def get_queryset(self):
        return (super().get_queryset().select_related("enrolled_device")
                                      .filter(enrolled_device__pk=self.kwargs["device_pk"]))

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["enrolled_device"] = ctx["object"].enrolled_device
        ctx["installed_artifacts"] = (self.object.installed_artifacts
                                                 .select_related("artifact_version__artifact")
                                                 .all()
                                                 .order_by("-updated_at"))
        ctx["installed_artifacts_count"] = ctx["installed_artifacts"].count()
        ctx["commands"] = (self.object.commands
                                      .select_related("artifact_version__artifact")
                                      .all()
                                      .order_by("-created_at"))
        ctx["commands_count"] = ctx["commands"].count()
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


class CreateEnrolledDeviceCustomCommandView(PermissionRequiredMixin, FormView):
    permission_required = "mdm.add_devicecommand"
    form_class = CustomCommandForm
    template_name = "mdm/enrolleddevice_create_custom_command.html"

    def dispatch(self, request, *args, **kwargs):
        self.enrolled_device = get_object_or_404(
            EnrolledDevice,
            pk=kwargs["pk"]
        )
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["enrolled_device"] = self.enrolled_device
        return ctx

    def form_valid(self, form):
        command = form.cleaned_data["command"]
        CustomCommand.create_for_device(self.enrolled_device, kwargs={"command": command}, queue=True)
        messages.info(self.request, "Custom command successfully created")
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
