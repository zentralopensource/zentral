from django.conf.urls import url
from django.views.decorators.csrf import csrf_exempt
from . import views

urlpatterns = [
    # django admin
    url(r'^$', views.IndexView.as_view(), name='index'),
    url(r'^installer_package/$', views.InstallerPackageView.as_view(), name='installer_package'),
    # API
    url(r'^job_details/$', csrf_exempt(views.JobDetailsView.as_view())),
    url(r'^post_job/$', csrf_exempt(views.PostJobView.as_view()))
]
