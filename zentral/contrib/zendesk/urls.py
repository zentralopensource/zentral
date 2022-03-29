from django.urls import path
from django.views.decorators.csrf import csrf_exempt
from . import views

app_name = "zendesk"
urlpatterns = [
    path('post_event/', csrf_exempt(views.PostEventView.as_view())),
]
