import logging
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.contrib.auth.views import redirect_to_login
from django.core.exceptions import PermissionDenied
from django.http import Http404, HttpResponseRedirect
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse
from django.views.generic import CreateView, DeleteView, DetailView, ListView, UpdateView, View
from zentral.conf import settings as zentral_settings
from zentral.utils.views import UserPaginationListView
from .backends.registry import backend_classes
from .forms import RealmGroupMappingForm, RealmGroupSearchForm, RealmTagMappingForm, RealmUserSearchForm
from .models import (Realm, RealmAuthenticationSession, RealmGroup, RealmGroupMapping, RealmTagMapping,
                     RealmUser, RealmUserGroupMembership)
from .utils import get_realm_user_mapped_groups


logger = logging.getLogger("zentral.realms.views")


class LocalUserRequiredMixin:
    """Verify that the current user is not a remote user and has authenticated locally."""

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect_to_login(self.request.get_full_path(),
                                     settings.LOGIN_URL,
                                     REDIRECT_FIELD_NAME)
        if request.user.is_remote:
            raise PermissionDenied("Remote users cannot access this view.")
        if request.realm_authentication_session.is_remote:
            raise PermissionDenied("Log in without using a realm to access this view.")
        return super().dispatch(request, *args, **kwargs)


class RealmListView(PermissionRequiredMixin, ListView):
    permission_required = "realms.view_realm"
    model = Realm

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["realms_count"] = ctx["object_list"].count()
        create_links = []
        if not self.request.realm_authentication_session.is_remote and self.request.user.has_perm("realms.add_realm"):
            create_links.extend(
                {"url": reverse("realms:create", args=(slug,)),
                 "anchor_text": backend_class.name}
                for slug, backend_class in backend_classes.items()
            )
        ctx["create_links"] = create_links
        return ctx


class CreateRealmView(LocalUserRequiredMixin, PermissionRequiredMixin, CreateView):
    permission_required = "realms.add_realm"
    template_name = "realms/realm_form.html"

    def dispatch(self, request, *args, **kwargs):
        self.backend = kwargs.pop("backend")
        if self.backend not in backend_classes:
            raise Http404
        return super().dispatch(request, *args, **kwargs)

    def get_form_class(self):
        return backend_classes.get(self.backend).get_form_class()

    def form_valid(self, form):
        self.object = form.save(commit=False)
        self.object.backend = self.backend
        self.object.save()
        return redirect(self.object)


class RealmView(PermissionRequiredMixin, DetailView):
    permission_required = "realms.view_realm"
    model = Realm

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        group_mappings = self.object.realmgroupmapping_set.all().order_by("claim", "value", "group__name")
        ctx["group_mappings"] = group_mappings
        ctx["group_mapping_count"] = group_mappings.count()
        tag_mappings = self.object.realmtagmapping_set.all().order_by("group_name", "tag__name")
        ctx["tag_mappings"] = tag_mappings
        ctx["tag_mapping_count"] = tag_mappings.count()
        if self.object.scim_enabled:
            ctx["scim_root_url"] = 'https://{}{}'.format(
                zentral_settings["api"]["fqdn"],
                reverse("realms_public:scim_resource_types", args=(self.object.pk,)).replace("/ResourceTypes", "/")
            )
        ctx["group_count"] = self.object.realmgroup_set.count()
        if ctx["group_count"] and self.request.user.has_perm("realms.view_realmgroup"):
            ctx["groups_url"] = reverse("realms:groups") + f"?realm={ self.object.pk }"
        ctx["user_count"] = self.object.realmuser_set.count()
        if ctx["user_count"] and self.request.user.has_perm("realms.view_realmuser"):
            ctx["users_url"] = reverse("realms:users") + f"?realm={ self.object.pk }"
        return ctx


class UpdateRealmView(LocalUserRequiredMixin, PermissionRequiredMixin, UpdateView):
    permission_required = "realms.change_realm"
    model = Realm
    fields = ("name",)

    def get_form_class(self):
        return self.object.backend_instance.get_form_class()


# realm groups


class RealmGroupListView(PermissionRequiredMixin, UserPaginationListView):
    permission_required = "realms.view_realmgroup"
    template_name = "realms/realmgroup_list.html"

    def get(self, request, *args, **kwargs):
        self.form = RealmGroupSearchForm(self.request.GET)
        self.form.is_valid()
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        return self.form.get_queryset()

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["form"] = self.form
        page = ctx["page_obj"]
        bc = []
        if page.number > 1:
            qd = self.request.GET.copy()
            qd.pop('page', None)
            ctx['reset_link'] = "?{}".format(qd.urlencode())
            reset_link = "?{}".format(qd.urlencode())
        else:
            reset_link = None
        if self.form.has_changed():
            bc.append((reverse("realms:groups"), "Groups"))
            bc.append((reset_link, "Search"))
        else:
            bc.append((reset_link, "Groups"))
        bc.append((None, f"page {page.number} of {page.paginator.num_pages}"))
        ctx["breadcrumbs"] = bc
        return ctx


class RealmGroupView(PermissionRequiredMixin, DetailView):
    permission_required = "realms.view_realmgroup"
    model = RealmGroup

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["children"] = list(self.object.realmgroup_set.all().order_by("display_name"))
        ctx["user_count"] = RealmUserGroupMembership.objects.filter(group=self.object).count()
        if ctx["user_count"] and self.request.user.has_perm("realms.view_realmuser"):
            ctx["users_url"] = reverse("realms:users") + f"?realm={self.object.realm.pk}&realm_group={self.object.pk}"
        return ctx


# realm users


class RealmUserListView(PermissionRequiredMixin, UserPaginationListView):
    permission_required = "realms.view_realmuser"
    template_name = "realms/realmuser_list.html"

    def get(self, request, *args, **kwargs):
        self.form = RealmUserSearchForm(self.request.GET)
        self.form.is_valid()
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        return self.form.get_queryset()

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["form"] = self.form
        page = ctx["page_obj"]
        bc = []
        if page.number > 1:
            qd = self.request.GET.copy()
            qd.pop('page', None)
            ctx['reset_link'] = "?{}".format(qd.urlencode())
            reset_link = "?{}".format(qd.urlencode())
        else:
            reset_link = None
        if self.form.has_changed():
            bc.append((reverse("realms:users"), "Users"))
            bc.append((reset_link, "Search"))
        else:
            bc.append((reset_link, "Users"))
        bc.append((None, f"page {page.number} of {page.paginator.num_pages}"))
        ctx["breadcrumbs"] = bc
        return ctx


class RealmUserView(PermissionRequiredMixin, DetailView):
    permission_required = "realms.view_realmuser"
    model = RealmUser


# group mappings


class CreateRealmGroupMappingView(LocalUserRequiredMixin, PermissionRequiredMixin, CreateView):
    permission_required = "realms.add_realmgroupmapping"
    model = RealmGroupMapping
    form_class = RealmGroupMappingForm

    def dispatch(self, request, *args, **kwargs):
        self.realm = get_object_or_404(Realm, pk=kwargs["pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["realm"] = self.realm
        return kwargs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["realm"] = self.realm
        return ctx

    def get_success_url(self):
        return "{}#{}".format(self.realm.get_absolute_url(), self.object.pk)


class UpdateRealmGroupMappingView(LocalUserRequiredMixin, PermissionRequiredMixin, UpdateView):
    permission_required = "realms.change_realmgroupmapping"
    model = RealmGroupMapping
    pk_url_kwarg = "gm_pk"
    form_class = RealmGroupMappingForm

    def dispatch(self, request, *args, **kwargs):
        self.realm = get_object_or_404(Realm, pk=kwargs["pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["realm"] = self.realm
        return kwargs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["realm"] = self.realm
        return ctx

    def get_success_url(self):
        return "{}#{}".format(self.realm.get_absolute_url(), self.object.pk)


class DeleteRealmGroupMappingView(LocalUserRequiredMixin, PermissionRequiredMixin, DeleteView):
    permission_required = "realms.delete_realmgroupmapping"
    model = RealmGroupMapping
    pk_url_kwarg = "gm_pk"

    def get_success_url(self):
        return self.object.realm.get_absolute_url()


# tag mappings


class CreateRealmTagMappingView(PermissionRequiredMixin, CreateView):
    permission_required = "realms.add_realmtagmapping"
    model = RealmTagMapping
    form_class = RealmTagMappingForm

    def dispatch(self, request, *args, **kwargs):
        self.realm = get_object_or_404(Realm, pk=kwargs["pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["realm"] = self.realm
        return kwargs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["realm"] = self.realm
        return ctx

    def get_success_url(self):
        return "{}#{}".format(self.realm.get_absolute_url(), self.object.pk)


class UpdateRealmTagMappingView(PermissionRequiredMixin, UpdateView):
    permission_required = "realms.change_realmtagmapping"
    model = RealmTagMapping
    pk_url_kwarg = "tm_pk"
    form_class = RealmTagMappingForm

    def dispatch(self, request, *args, **kwargs):
        self.realm = get_object_or_404(Realm, pk=kwargs["pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["realm"] = self.realm
        return kwargs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["realm"] = self.realm
        return ctx

    def get_success_url(self):
        return "{}#{}".format(self.realm.get_absolute_url(), self.object.pk)


class DeleteRealmTagMappingView(PermissionRequiredMixin, DeleteView):
    permission_required = "realms.delete_realmtagmapping"
    model = RealmTagMapping
    pk_url_kwarg = "tm_pk"

    def get_success_url(self):
        return self.object.realm.get_absolute_url()


# SSO Test views


class TestRealmView(LocalUserRequiredMixin, PermissionRequiredMixin, View):
    permission_required = "realms.view_realm"

    def post(self, request, *args, **kwargs):
        realm = get_object_or_404(Realm, pk=kwargs["pk"])
        callback = "realms.utils.test_callback"
        callback_kwargs = {}
        redirect_url = None
        try:
            redirect_url = realm.backend_instance.initialize_session(request, callback, **callback_kwargs)
        except Exception:
            logger.exception("Could not get realm %s redirect URL", realm.pk)
        if redirect_url:
            return HttpResponseRedirect(redirect_url)
        else:
            messages.error(request, "Configuration error")
            return HttpResponseRedirect(realm.get_absolute_url())


class RealmAuthenticationSessionView(LocalUserRequiredMixin, PermissionRequiredMixin, DetailView):
    permission_required = "realms.view_realm"
    model = RealmAuthenticationSession
    pk_url_kwarg = "ras_pk"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ras = ctx["object"]

        # session expiry
        computed_expiry = ctx["computed_expiry"] = ras.computed_expiry()
        ctx["login_session_expire_at_browser_close"] = computed_expiry == 0
        if ras.expires_at:
            idp_expiry_delta = ras.expires_at - ras.updated_at
            ctx["idp_expiry_age"] = 86400 * idp_expiry_delta.days + idp_expiry_delta.seconds

        # realm user
        realm_user = ctx["realm_user"] = ras.user
        if not realm_user.email:
            ctx["error"] = "Missing email. Cannot be used for Zentral login."

        # groups
        ctx["mapped_groups"] = sorted(get_realm_user_mapped_groups(realm_user), key=lambda g: g.name)
        ctx["mapped_group_count"] = len(ctx["mapped_groups"])

        return ctx
