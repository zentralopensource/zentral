from django.urls import path
from django.views.decorators.csrf import csrf_exempt
from . import public_views

app_name = "santa_public"
urlpatterns = [
    path('sync/preflight/<str:machine_id>',
         csrf_exempt(public_views.PreflightView.as_view()), name='preflight'),
    path('sync/ruledownload/<str:machine_id>',
         csrf_exempt(public_views.RuleDownloadView.as_view()), name='ruledownload'),
    path('sync/eventupload/<str:machine_id>',
         csrf_exempt(public_views.EventUploadView.as_view()), name='eventupload'),
    path('sync/postflight/<str:machine_id>',
         csrf_exempt(public_views.PostflightView.as_view()), name='postflight'),
    # deprecated URLs
    path('sync/<str:enrollment_secret>/preflight/<str:machine_id>',
         csrf_exempt(public_views.PreflightView.as_view()), name='deprecated_preflight'),
    path('sync/<str:enrollment_secret>/ruledownload/<str:machine_id>',
         csrf_exempt(public_views.RuleDownloadView.as_view()), name='deprecated_ruledownload'),
    path('sync/<str:enrollment_secret>/eventupload/<str:machine_id>',
         csrf_exempt(public_views.EventUploadView.as_view()), name='deprecated_eventupload'),
    path('sync/<str:enrollment_secret>/postflight/<str:machine_id>',
         csrf_exempt(public_views.PostflightView.as_view()), name='deprecated_postflight'),
]
