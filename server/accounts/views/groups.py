from collections import OrderedDict
import logging
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.contrib.auth.models import Group
from django.core.exceptions import ObjectDoesNotExist
from django.db.models import Exists, OuterRef
from django.db.models.functions import Lower
from django.urls import reverse, reverse_lazy
from django.views.generic import CreateView, DeleteView, DetailView, ListView, UpdateView
from accounts.forms import GroupForm
from accounts.models import ProvisionedRole


logger = logging.getLogger("zentral.accounts.views.groups")


class GroupsView(PermissionRequiredMixin, ListView):
    permission_required = 'auth.view_group'
    template_name = "accounts/group_list.html"

    def get_queryset(self):
        return Group.objects.raw(
            "select g.*, g.name,"
            "(select count(*) from accounts_user u "
            " join accounts_user_groups ug on (ug.user_id = u.id) "
            " where ug.group_id=g.id and is_service_account = TRUE) service_account_count,"
            "(select count(*) from accounts_user u "
            " join accounts_user_groups ug on (ug.user_id = u.id) "
            " where ug.group_id=g.id and is_service_account = FALSE) user_count,"
            "(select count(*) from realms_rolemapping rrm"
            " where rrm.group_id=g.id) role_mapping_count,"
            "not exists(select * from accounts_provisionedrole where group_id = g.id) can_be_edited "
            "from auth_group g order by g.name"
        )


class CreateGroupView(PermissionRequiredMixin, CreateView):
    permission_required = 'auth.add_group'
    model = Group
    form_class = GroupForm
    template_name = "accounts/group_form.html"

    def get_success_url(self):
        return reverse("accounts:group", args=(self.object.pk,))


class GroupView(PermissionRequiredMixin, DetailView):
    permission_required = 'auth.view_group'
    model = Group
    template_name = "accounts/group_detail.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        permissions = OrderedDict()
        permission_count = 0
        for permission in self.object.permissions.select_related("content_type").all():
            content_type = permission.content_type
            codename = permission.codename.replace(f"_{content_type.model}", "")
            permissions.setdefault(content_type, []).append(codename)
            permission_count += 1
        ctx["permissions"] = permissions.items()
        ctx["permission_count"] = permission_count
        qs = self.object.user_set.all().order_by("username", "email", "last_name", "first_name")
        users = qs.filter(is_service_account=False)
        ctx["users"] = users
        ctx["user_count"] = users.count()
        service_accounts = qs.filter(is_service_account=True)
        ctx["service_accounts"] = service_accounts
        ctx["service_account_count"] = service_accounts.count()
        # role mappings
        role_mappings = (
            self.object.rolemapping_set.all()
                       .select_related("realm_group")
                       .order_by(Lower("realm_group__display_name"))
        )
        ctx["role_mappings"] = role_mappings
        ctx["role_mapping_count"] = role_mappings.count()
        try:
            self.object.provisioned_role
        except ObjectDoesNotExist:
            ctx["can_be_edited"] = True
        else:
            ctx["can_be_edited"] = False
        return ctx


class UpdateGroupView(PermissionRequiredMixin, UpdateView):
    permission_required = 'auth.change_group'
    queryset = Group.objects.filter(~Exists(ProvisionedRole.objects.filter(group=OuterRef('pk'))))
    form_class = GroupForm
    template_name = "accounts/group_form.html"

    def get_success_url(self):
        return reverse("accounts:group", args=(self.object.pk,))


class DeleteGroupView(PermissionRequiredMixin, DeleteView):
    permission_required = 'auth.delete_group'
    queryset = Group.objects.filter(~Exists(ProvisionedRole.objects.filter(group=OuterRef('pk'))))
    template_name = "accounts/group_confirm_delete.html"
    success_url = reverse_lazy("accounts:groups")
