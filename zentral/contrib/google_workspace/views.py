import logging
from django.core.exceptions import PermissionDenied
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.contrib import messages
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse_lazy
from django.views.generic import DetailView, TemplateView, ListView, View
from zentral.utils.views import CreateViewWithAudit, DeleteViewWithAudit, UpdateViewWithAudit
from .api_client import APIClient
from .forms import ConnectionForm, GroupTagMappingForm
from .models import Connection, GroupTagMapping


logger = logging.getLogger('zentral.contrib.google_workspace.views')


class IndexView(LoginRequiredMixin, TemplateView):
    template_name = "google_workspace/index.html"

    def get_context_data(self, **kwargs):
        if not self.request.user.has_module_perms("google_workspace"):
            raise PermissionDenied("Not allowed")
        ctx = super().get_context_data(**kwargs)
        return ctx


class ConnectionsView(PermissionRequiredMixin, ListView):
    permission_required = "google_workspace.view_connection"
    model = Connection


class CreateConnectionView(PermissionRequiredMixin, CreateViewWithAudit):
    permission_required = "google_workspace.add_connection"
    model = Connection
    form_class = ConnectionForm

    def form_valid(self, form):
        connection = form.save()
        api_client = APIClient.from_connection(connection)
        return HttpResponseRedirect(api_client.start_flow())


class ConnectionRedirectView(PermissionRequiredMixin, View):
    permission_required = "google_workspace.add_connection"

    def get(self, request, *args, **kwargs):
        state = request.GET.get("state")
        code = request.GET.get("code")
        try:
            api_client = APIClient.from_oauth2_state(state)
            api_client.complete_authorization(code)
        except Exception:
            logger.exception("Unable to authorize connection.")
            messages.error(self.request, "Authorization failed.")

        return redirect(api_client.connection)


class ConnectionView(PermissionRequiredMixin, DetailView):
    permission_required = "google_workspace.view_connection"
    model = Connection

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["group_tag_mappings"] = self.object.grouptagmapping_set.prefetch_related(
            "tags__taxonomy",
            "tags__meta_business_unit").all()
        ctx["group_tag_mappings_count"] = ctx["group_tag_mappings"].count()

        authorization_needed = False
        try:
            api_client = APIClient.from_connection(self.object)
            api_client.get_group("noreply@zentral.com")

            ctx["api_client"] = api_client
        except Exception as e:
            authorization_needed = True
            if "refresh_token" in str(e):
                message = f"Configuration of {self.object.name} is invalid. Missing refresh token."
            else:
                message = f"Authorization needed for {self.object.name} connection"
            logger.info(message, extra={'request': self.request})
            messages.error(self.request, message)
        ctx["connection_authorized"] = not authorization_needed
        return ctx


class AuthorizeConnectionView(PermissionRequiredMixin, View):
    permission_required = "google_workspace.view_connection"

    def get(self, request, *args, **kwargs):
        api_client = APIClient.from_connection(get_object_or_404(Connection, pk=kwargs["pk"]))
        redirect_url = api_client.start_flow()
        return HttpResponseRedirect(redirect_url)


class UpdateConnectionView(PermissionRequiredMixin, UpdateViewWithAudit):
    permission_required = "google_workspace.change_connection"
    model = Connection
    form_class = ConnectionForm

    def form_valid(self, form):
        connection = form.save()
        if form.reauthorization_required:
            api_client = APIClient.from_connection(connection)
            return HttpResponseRedirect(api_client.start_flow())
        return redirect(connection)


class DeleteConnectionView(PermissionRequiredMixin, DeleteViewWithAudit):
    permission_required = "google_workspace.delete_connection"
    success_url = reverse_lazy("google_workspace:connections")

    def get_queryset(self):
        return Connection.objects.can_be_deleted()


class GroupTagMappingFormMixin():
    model = GroupTagMapping
    form_class = GroupTagMappingForm

    def dispatch(self, request, *args, **kwargs):
        self.connection = get_object_or_404(Connection, pk=kwargs["conn_pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["connection"] = self.connection
        return ctx

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["connection"] = self.connection
        return kwargs


class CreateGroupTagMappingView(PermissionRequiredMixin, GroupTagMappingFormMixin, CreateViewWithAudit):
    permission_required = "google_workspace.add_grouptagmapping"


class UpdateGroupTagMappingView(PermissionRequiredMixin, GroupTagMappingFormMixin, UpdateViewWithAudit):
    permission_required = "google_workspace.change_grouptagmapping"


class DeleteGroupTagMappingView(PermissionRequiredMixin, DeleteViewWithAudit):
    permission_required = "google_workspace.delete_grouptagmapping"
    model = GroupTagMapping

    def get_object(self):
        group_tag_mapping = (self.model.objects
                             .select_related("connection")
                             .get(pk=self.kwargs["pk"]))
        self.connection = group_tag_mapping.connection
        return group_tag_mapping

    def get_success_url(self):
        return self.connection.get_absolute_url()
