from datetime import timedelta
from django.conf import settings
from django.contrib import messages
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.utils import timezone


def force_password_change_middleware(get_response):
    max_password_age = timedelta(days=getattr(settings, "MAX_PASSWORD_AGE_DAYS", 30))
    password_change_url = reverse("password_change")
    ok_url = set([password_change_url,
                  reverse("logout"),
                  reverse("users:nginx_auth_request")])  # TODO: VERIFY

    def middleware(request):
        user = request.user
        if user.is_authenticated and \
           not user.is_remote and \
           not request.session.get("_realm_authentication_session") and \
           user.has_usable_password() and \
           user.password_updated_at is not None and \
           (timezone.now() - user.password_updated_at) > max_password_age and \
           request.path not in ok_url:
            messages.warning(request, "Your password has expired. Please pick a new one.")
            return HttpResponseRedirect(password_change_url)
        response = get_response(request)
        return response

    return middleware
