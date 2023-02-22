from django.urls import path
from django.views.decorators.csrf import csrf_exempt
from . import views

app_name = "santa_public"
urlpatterns = [
        # API
    path('sync/<str:enrollment_secret>/preflight/<str:machine_id>',
         csrf_exempt(views.PreflightView.as_view()), name='preflight'),
    path('sync/<str:enrollment_secret>/ruledownload/<str:machine_id>',
         csrf_exempt(views.RuleDownloadView.as_view()), name='ruledownload'),
    path('sync/<str:enrollment_secret>/eventupload/<str:machine_id>',
         csrf_exempt(views.EventUploadView.as_view()), name='eventupload'),
    path('sync/<str:enrollment_secret>/postflight/<str:machine_id>',
         csrf_exempt(views.PostflightView.as_view()), name='postflight'),
]
