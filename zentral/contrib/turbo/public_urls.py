from django.urls import path
from django.views.decorators.csrf import csrf_exempt
from . import public_views

app_name = "turbo_public"
urlpatterns = [
    path('enroll/', csrf_exempt(public_views.EnrollView.as_view()), name='enroll'),
    path('enrollment/', csrf_exempt(public_views.EnrollmentInfoView.as_view()), name='enrollment'),
    path('config/', csrf_exempt(public_views.ConfigView.as_view()), name='config'),
    path('results/', csrf_exempt(public_views.ResultsView.as_view()), name='results'),
    path('status/', csrf_exempt(public_views.StatusView.as_view()), name='status'),
    path('inventory/', csrf_exempt(public_views.InventoryView.as_view()), name='inventory'),
    path('uploads/', csrf_exempt(public_views.UploadMintView.as_view()), name='uploads'),
    # the fallback destination when the storage cannot presign a PUT; the token names one row
    path('uploads/<str:token>/', csrf_exempt(public_views.HostedUploadView.as_view()),
         name='upload'),
]
