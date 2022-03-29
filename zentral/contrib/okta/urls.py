from django.urls import path
from django.views.decorators.csrf import csrf_exempt
from . import views

app_name = "okta"
urlpatterns = [
    path('events/', csrf_exempt(views.EventHookView.as_view()), name='event_hook'),
]
