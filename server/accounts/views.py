from django.contrib import messages
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse, reverse_lazy
from django.views.generic import FormView, ListView, TemplateView, View
from .forms import AddUserForm, UpdateUserForm
from .models import User


class CanManageUsersMixin(PermissionRequiredMixin):
    permission_required = ('accounts.add_user', 'accounts.change_user', 'accounts.delete_user')


class UsersView(CanManageUsersMixin, ListView):
    model = User


class NginxAuthRequestView(View):
    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated():
            if request.is_ajax() or request.META.get('HTTP_ACCEPT', '').startswith('application/json'):
                status_code = 403
            else:
                status_code = 401
            response = HttpResponse('Signed out')
            response.status_code = status_code
            return response
        else:
            return HttpResponse("OK")


class AddUserView(CanManageUsersMixin, FormView):
    template_name = "accounts/user_form.html"
    form_class = AddUserForm
    success_url = reverse_lazy("users:list")

    def form_valid(self, form):
        form.save(self.request)
        return super().form_valid(form)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["title"] = "Send an email invitation"
        return ctx


class UpdateUserView(CanManageUsersMixin, FormView):
    template_name = "accounts/user_form.html"
    form_class = UpdateUserForm
    success_url = reverse_lazy("users:list")

    def dispatch(self, request, *args, **kwargs):
        self.user = get_object_or_404(User, pk=kwargs["pk"])
        if not self.user.editable():
            return HttpResponseRedirect(self.success_url)
        return super().dispatch(request, *args, **kwargs)

    def get_initial(self):
        return {"username": self.user.username,
                "email": self.user.email,
                "is_superuser": self.user.is_superuser}

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["instance"] = self.user
        return kwargs

    def form_valid(self, form):
        form.save(self.request)
        return super().form_valid(form)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["managed_user"] = self.user
        ctx["title"] = "Update user {}".format(self.user)
        return ctx


class DeleteUserView(CanManageUsersMixin, TemplateView):
    template_name = "accounts/delete_user.html"

    def dispatch(self, request, *args, **kwargs):
        self.user = get_object_or_404(User, pk=kwargs["pk"])
        if not self.user.deletable():
            return HttpResponseRedirect(reverse("users:list"))
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["managed_user"] = self.user
        return ctx

    def post(self, request, *args, **kwargs):
        msg = "User {} deleted".format(self.user)
        self.user.delete()
        messages.info(request, msg)
        return HttpResponseRedirect(reverse("users:list"))
