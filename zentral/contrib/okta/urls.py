from django.conf.urls import url
from django.views.decorators.csrf import csrf_exempt
from . import views

app_name = "okta"
urlpatterns = [
    url(r'^events/$', csrf_exempt(views.EventHookView.as_view()), name='event_hook'),
]
