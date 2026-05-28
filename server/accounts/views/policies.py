import logging
import re

from django.contrib.auth.mixins import PermissionRequiredMixin
from django.urls import NoReverseMatch, reverse, reverse_lazy
from django.utils.html import escape, format_html
from django.utils.safestring import mark_safe
from django.views.generic import DetailView

from accounts.forms import PolicyForm
from accounts.models import Policy
from pbac.utils import signal_policy_change
from zentral.utils.views import CreateViewWithAudit, DeleteViewWithAudit, UpdateViewWithAudit, UserPaginationListView


logger = logging.getLogger("zentral.accounts.views.policies")


# Principal entity references in a CEDAR policy source.
# - Role::"<pk>"            -> accounts:group
# - User::"<pk>"            -> accounts:user
# - ServiceAccount::"<pk>"  -> accounts:user (service accounts use the
#                              same User detail page)
# The \b anchor keeps "BServiceAccount" / "MyRole" etc. from matching.
_PRINCIPAL_REF_RE = re.compile(r'\b(Role|User|ServiceAccount)::"([^"]+)"')
_PRINCIPAL_URL_NAMES = {
    "Role": "accounts:group",
    "User": "accounts:user",
    "ServiceAccount": "accounts:user",
}


def _linkify_principals(source):
    """Render a CEDAR policy source with anchor tags around principal
    references. Returns a SafeString. Non-principal references (Action,
    resource types) are escaped as plain text. References whose id isn't
    a valid pk for the corresponding view (e.g. an unresolved
    provisioning UID) are left as escaped plain text — no broken link.
    """
    parts = []
    last_end = 0
    for m in _PRINCIPAL_REF_RE.finditer(source):
        parts.append(escape(source[last_end:m.start()]))
        type_, pk = m.group(1), m.group(2)
        try:
            url = reverse(_PRINCIPAL_URL_NAMES[type_], args=[pk])
        except NoReverseMatch:
            parts.append(escape(m.group(0)))
        else:
            parts.append(format_html('{}::"<a href="{}">{}</a>"', type_, url, pk))
        last_end = m.end()
    parts.append(escape(source[last_end:]))
    return mark_safe("".join(parts))


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

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["source_html"] = _linkify_principals(self.object.source)
        return ctx


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
