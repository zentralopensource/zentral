from django.contrib.auth import views as auth_views
from accounts.events import post_password_change_event, post_password_reset_request_event
from accounts.forms import PasswordResetForm


class PasswordChangeView(auth_views.PasswordChangeView):
    def form_valid(self, form):
        response = super().form_valid(form)
        post_password_change_event(self.request, form.user, password_reset=False)
        return response


class PasswordResetView(auth_views.PasswordResetView):
    form_class = PasswordResetForm

    def form_valid(self, form):
        response = super().form_valid(form)
        post_password_reset_request_event(self.request, form.cleaned_data["email"], form.users)
        return response


class PasswordResetConfirmView(auth_views.PasswordResetConfirmView):
    def form_valid(self, form):
        response = super().form_valid(form)
        post_password_change_event(self.request, form.user, password_reset=True)
        return response
