import logging
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.urls import reverse_lazy
from zentral.utils.views import CreateViewWithAudit, DeleteViewWithAudit, UpdateViewWithAudit, UserPaginationListView
from django.views.generic import DetailView
from accounts.forms import PolicyForm
from accounts.models import Policy
from accounts.pbac.utils import signal_policy_change


logger = logging.getLogger("zentral.accounts.views.policies")


class PoliciesView(PermissionRequiredMixin, UserPaginationListView):
    permission_required = 'accounts.view_policy'
    model = Policy

    def get_queryset(self):
        return super().get_queryset().order_by("name")

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        page = ctx['page_obj']
        bc = []
        if page.number > 1:
            qd = self.request.GET.copy()
            qd.pop("page", None)
            reset_link = "?{}".format(qd.urlencode())
        else:
            reset_link = None
        bc.append((reset_link, "Policies"))
        bc.append((None, "page {} of {}".format(page.number, page.paginator.num_pages)))
        ctx["breadcrumbs"] = bc
        return ctx


class CreatePolicyView(PermissionRequiredMixin, CreateViewWithAudit):
    permission_required = 'accounts.add_policy'
    model = Policy
    form_class = PolicyForm

    def on_commit_callback_extra(self):
        signal_policy_change()


class PolicyView(PermissionRequiredMixin, DetailView):
    permission_required = 'accounts.view_policy'
    model = Policy


class UpdatePolicyView(PermissionRequiredMixin, UpdateViewWithAudit):
    permission_required = 'accounts.change_policy'
    form_class = PolicyForm

    def get_queryset(self):
        return Policy.objects.for_update()

    def on_commit_callback_extra(self):
        signal_policy_change()


class DeletePolicyView(PermissionRequiredMixin, DeleteViewWithAudit):
    permission_required = 'accounts.delete_policy'
    model = Policy
    success_url = reverse_lazy("accounts:policies")

    def get_queryset(self):
        return Policy.objects.for_deletion()

    def on_commit_callback_extra(self):
        signal_policy_change()
