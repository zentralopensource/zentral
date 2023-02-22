from django.urls import path
from django.views.decorators.csrf import csrf_exempt
from . import public_views

app_name = "osquery_public"
urlpatterns = [
    # osquery API
    path('enroll', csrf_exempt(public_views.EnrollView.as_view()), name='enroll'),
    path('config', csrf_exempt(public_views.ConfigView.as_view()), name='config'),
    path('carver/start', csrf_exempt(public_views.StartFileCarvingView.as_view()), name='carver_start'),
    path('carver/continue', csrf_exempt(public_views.ContinueFileCarvingView.as_view()), name='carver_continue'),
    path('distributed/read', csrf_exempt(public_views.DistributedReadView.as_view()), name='distributed_read'),
    path('distributed/write', csrf_exempt(public_views.DistributedWriteView.as_view()), name='distributed_write'),
    path('log', csrf_exempt(public_views.LogView.as_view()), name='log'),
]
