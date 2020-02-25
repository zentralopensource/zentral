import logging
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import Http404, HttpResponseRedirect
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse
from django.utils.http import is_safe_url
from django.views.generic import CreateView, DetailView, ListView, UpdateView, View
from .backends import backend_classes
from .models import Realm


logger = logging.getLogger("zentral.realms.views")


class RealmListView(LoginRequiredMixin, ListView):
    model = Realm

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["realms_count"] = ctx["object_list"].count()
        ctx["create_links"] = [
            {"url": reverse("realms:create", args=(slug,)),
             "anchor_text": backend_class.name}
            for slug, backend_class in backend_classes.items()
        ]
        return ctx


class CreateRealmView(LoginRequiredMixin, CreateView):
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


class RealmView(LoginRequiredMixin, DetailView):
    model = Realm


class UpdateRealmView(LoginRequiredMixin, UpdateView):
    model = Realm
    fields = ("name",)

    def get_form_class(self):
        return self.object.backend_instance.get_form_class()


class ZentralLoginView(View):
    def post(self, request, *args, **kwargs):
        realm = get_object_or_404(Realm, pk=kwargs["pk"], enabled_for_login=True)
        callback = "realms.utils.login_callback"
        callback_kwargs = {}
        next_url = request.POST.get("next")
        if next_url and is_safe_url(url=next_url,
                                    allowed_hosts={request.get_host()},
                                    require_https=request.is_secure()):
            callback_kwargs["next_url"] = next_url
        redirect_url = None
        try:
            redirect_url = realm.backend_instance.initialize_session(callback, **callback_kwargs)
        except Exception:
            logger.exception("Could not get realm %s redirect URL", realm.pk)
        else:
            if redirect_url:
                return HttpResponseRedirect(redirect_url)
            else:
                raise ValueError("Empty realm {} redirect URL".format(realm.pk))
