import logging
import re

from django.contrib.auth.mixins import PermissionRequiredMixin
from django.contrib.auth.models import Group
from django.urls import NoReverseMatch, reverse, reverse_lazy
from django.utils.html import escape, format_html
from django.utils.safestring import mark_safe
from django.views.generic import DetailView, TemplateView

from accounts.forms import PolicyForm
from accounts.models import Policy, User
from pbac.engine import ActionGroupBasename, engine
from pbac.schema import build_schema_ir
from pbac.utils import signal_policy_change
from zentral.utils.views import (
    CreateViewWithAudit,
    DeleteViewWithAudit,
    LocalSuperuserRequiredMixin,
    UpdateViewWithAudit,
    UserPaginationListView,
)


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


class PoliciesSchemaView(PermissionRequiredMixin, TemplateView):
    permission_required = 'accounts.view_policy'
    template_name = "accounts/policies_schema.html"

    @staticmethod
    def build_namespaces(ir):
        """Translate a SchemaIR into a flat list of namespaces ready for
        template rendering. Each namespace bundles its entity types and its
        concrete actions (action groups themselves are dropped — they're an
        internal schema mechanism, not something operators reason about
        directly).
        """
        namespaces = []
        for ns_id in sorted(ir.namespaces, key=lambda k: (k is None, k or "")):
            ns = ir.namespaces[ns_id]
            entity_types = [
                {
                    "name": et.name,
                    "qualified_name": et.qualified_name,
                    "parents": list(et.parents),
                    "attrs": [(name, str(spec)) for name, spec in sorted(et.attrs.items())],
                }
                for _, et in sorted(ns.entity_types.items())
            ]
            actions = []
            for action_id, action in sorted(ns.actions.items()):
                if action.applies_to is None:
                    # Action group entity (e.g. AdminActions); skip — represented as
                    # badges on the concrete actions that belong to it.
                    continue
                basenames = sorted({
                    bn.value for bn in (ActionGroupBasename.from_group_id(gid) for gid, _ in action.member_of)
                    if bn is not None
                })
                actions.append({
                    "id": action_id,
                    "qualified_id": f'{ns_id}::Action::"{action_id}"' if ns_id else f'Action::"{action_id}"',
                    "group_basenames": basenames,
                    "principals": list(action.applies_to.principals),
                    "resources": list(action.applies_to.resources),
                    "context": (
                        sorted((name, str(spec)) for name, spec in action.applies_to.context.items())
                        if action.applies_to.context else []
                    ),
                })
            if not entity_types and not actions:
                continue
            namespaces.append({
                "id": ns_id,
                "display": ns_id or "(global)",
                "entity_types": entity_types,
                "actions": actions,
            })
        return namespaces

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["namespaces"] = self.build_namespaces(build_schema_ir(engine))
        ctx["action_group_basenames"] = list(ActionGroupBasename)
        return ctx


# Policy mutation is gated by LocalSuperuserRequiredMixin, not by a CEDAR-grantable
# permission: the ability to author policies is effectively root (anyone with it can
# write themselves into any role), so the gate must live outside the policy system
# it would otherwise bound. accounts.add_policy / change_policy / delete_policy
# still exist on the model but are not consulted for these views.


class CreatePolicyView(LocalSuperuserRequiredMixin, CreateViewWithAudit):
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


class UpdatePolicyView(LocalSuperuserRequiredMixin, UpdateViewWithAudit):
    form_class = PolicyForm

    def get_queryset(self):
        return Policy.objects.for_update()

    def on_commit_callback_extra(self):
        signal_policy_change()


class DeletePolicyView(LocalSuperuserRequiredMixin, DeleteViewWithAudit):
    model = Policy
    success_url = reverse_lazy("accounts:policies")

    def get_queryset(self):
        return Policy.objects.for_deletion()

    def on_commit_callback_extra(self):
        signal_policy_change()
