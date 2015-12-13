from django.conf.urls import url
from django.views.decorators.csrf import csrf_exempt
from . import views

urlpatterns = [
    # API
    url(r'^job_details/(?P<machine_serial_number>\S+)/$', views.JobDetailsView.as_view()),
    url(r'^post_job/$', csrf_exempt(views.PostJobView.as_view()))
]
