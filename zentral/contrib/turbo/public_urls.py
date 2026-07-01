from django.urls import path
from django.views.decorators.csrf import csrf_exempt
from . import public_views

app_name = "turbo_public"
urlpatterns = [
    path('enroll/', csrf_exempt(public_views.EnrollView.as_view()), name='enroll'),
    path('config/', csrf_exempt(public_views.ConfigView.as_view()), name='config'),
    path('results/', csrf_exempt(public_views.ResultsView.as_view()), name='results'),
    path('status/', csrf_exempt(public_views.StatusView.as_view()), name='status'),
    path('inventory/', csrf_exempt(public_views.InventoryView.as_view()), name='inventory'),
]
