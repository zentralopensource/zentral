import logging
import re

from django.contrib.auth.mixins import PermissionRequiredMixin
from django.contrib.auth.models import Group
from django.urls import NoReverseMatch, reverse, reverse_lazy
from django.utils.html import escape, format_html
from django.utils.safestring import mark_safe
from django.views.generic import DetailView

from accounts.forms import PolicyForm
from accounts.models import Policy, User
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


def _principal_display_names(source):
    """Walk a policy source and resolve every (type, pk) principal
    reference to a display name, in 0-2 queries total. Returns
    ``{(type, pk_int): name}``. Missing principals are simply absent
    from the dict — callers should default to no tooltip.
    """
    role_pks, user_pks = set(), set()
    for m in _PRINCIPAL_REF_RE.finditer(source):
        type_, pk_str = m.group(1), m.group(2)
        try:
            pk = int(pk_str)
        except ValueError:
            continue
        (role_pks if type_ == "Role" else user_pks).add(pk)
    names = {}
    if role_pks:
        for pk, name in Group.objects.filter(pk__in=role_pks).values_list("pk", "name"):
            names[("Role", pk)] = name
    if user_pks:
        for pk, username in User.objects.filter(pk__in=user_pks).values_list("pk", "username"):
            # The username applies whether the policy says User::"<pk>"
            # or ServiceAccount::"<pk>" — they share the User model. A
            # mismatched type still gives the operator useful info ("a
            # user with this pk exists, here's its username") so we
            # populate both keys.
            names[("User", pk)] = username
            names[("ServiceAccount", pk)] = username
    return names


def _linkify_principals(source):
    """Render a CEDAR policy source with anchor tags around principal
    references. Returns a SafeString. Non-principal references (Action,
    resource types) are escaped as plain text. References whose id isn't
    a valid pk for the corresponding view (e.g. an unresolved
    provisioning UID) are left as escaped plain text — no broken link.
    The anchor's ``title`` attribute carries the principal's display
    name when we can resolve it, giving operators a native (no-JS)
    tooltip on hover.
    """
    display_names = _principal_display_names(source)
    parts = []
    last_end = 0
    for m in _PRINCIPAL_REF_RE.finditer(source):
        parts.append(escape(source[last_end:m.start()]))
        type_, pk_str = m.group(1), m.group(2)
        try:
            url = reverse(_PRINCIPAL_URL_NAMES[type_], args=[pk_str])
        except NoReverseMatch:
            parts.append(escape(m.group(0)))
        else:
            try:
                pk_int = int(pk_str)
            except ValueError:
                pk_int = None
            display_name = display_names.get((type_, pk_int)) if pk_int is not None else None
            if display_name:
                parts.append(format_html(
                    '<a href="{}" title="{}">{}</a>',
                    url, display_name, m.group(0),
                ))
            else:
                parts.append(format_html('<a href="{}">{}</a>', url, m.group(0)))
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
