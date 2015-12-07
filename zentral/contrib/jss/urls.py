from django.conf.urls import url
from django.views.decorators.csrf import csrf_exempt
from . import views

urlpatterns = [
    # API
    url(r'^post_event/$', csrf_exempt(views.PostEventView.as_view()), name='post_event'),
]
