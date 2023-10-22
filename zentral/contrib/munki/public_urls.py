from django.urls import path
from django.views.decorators.csrf import csrf_exempt
from . import public_views

app_name = "munki_public"
urlpatterns = [
    path('enroll/', csrf_exempt(public_views.EnrollView.as_view()), name='enroll'),
    path('job_details/', csrf_exempt(public_views.JobDetailsView.as_view()), name="job_details"),
    path('post_job/', csrf_exempt(public_views.PostJobView.as_view()), name="post_job"),
]
