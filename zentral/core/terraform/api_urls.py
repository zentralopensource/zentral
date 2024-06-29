from django.urls import path
from django.views.decorators.csrf import csrf_exempt
from .api_views import BackendLockView, BackendStateView


app_name = "terraform_api"
urlpatterns = [
    path('backend/<slug:slug>/', csrf_exempt(BackendStateView.as_view()), name="backend_state"),
    path('backend/<slug:slug>/lock/', csrf_exempt(BackendLockView.as_view()), name="backend_lock"),
]
