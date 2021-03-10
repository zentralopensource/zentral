import logging
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.contrib.auth.models import Group
from django.urls import reverse, reverse_lazy
from django.views.generic import CreateView, DeleteView, DetailView, ListView, UpdateView


logger = logging.getLogger("zentral.accounts.views.groups")


class CanManageGroupsMixin(PermissionRequiredMixin):
    permission_required = ('accounts.add_group', 'accounts.change_group', 'accounts.delete_group',
                           'accounts.change_user')


class GroupsView(CanManageGroupsMixin, ListView):
    model = Group
    template_name = "accounts/group_list.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        return ctx


class CreateGroupView(CanManageGroupsMixin, CreateView):
    model = Group
    fields = "__all__"
    template_name = "accounts/group_form.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        return ctx

    def get_success_url(self):
        return reverse("accounts:group", args=(self.object.pk,))


class GroupView(CanManageGroupsMixin, DetailView):
    model = Group
    template_name = "accounts/group_detail.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        return ctx


class UpdateGroupView(CanManageGroupsMixin, UpdateView):
    model = Group
    fields = "__all__"
    template_name = "accounts/group_form.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        return ctx

    def get_success_url(self):
        return reverse("accounts:group", args=(self.object.pk,))


class DeleteGroupView(CanManageGroupsMixin, DeleteView):
    model = Group
    template_name = "accounts/group_confirm_delete.html"
    success_url = reverse_lazy("accounts:groups")

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        return ctx
