from django.conf.urls import url
from django.views.decorators.csrf import csrf_exempt
from . import views

app_name = "zendesk"
urlpatterns = [
    url(r'^post_event/$', csrf_exempt(views.PostEventView.as_view())),
]
