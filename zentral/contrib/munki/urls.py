from django.conf.urls import url
from django.views.decorators.csrf import csrf_exempt
from . import views

urlpatterns = [
    # API
    url(r'^last_seen_report/(?P<machine_serial_number>\S+)/$', views.LastSeenReportView.as_view()),
    url(r'^post_reports/$', csrf_exempt(views.PostReportsView.as_view()))
]
