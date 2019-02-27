from django.conf.urls import url
from rest_framework.urlpatterns import format_suffix_patterns
from .api_views import (ConfigurationDetail, ConfigurationList,
                        EnrollmentDetail, EnrollmentList)


app_name = "osquery_api"
urlpatterns = [
    url('^configurations/$', ConfigurationList.as_view(), name="configurations"),
    url('^configurations/(?P<pk>\d+)/$', ConfigurationDetail.as_view(), name="configuration"),
    url('^enrollments/$', EnrollmentList.as_view(), name="enrollments"),
    url('^enrollments/(?P<pk>\d+)/$', EnrollmentDetail.as_view(), name="enrollment"),
]


urlpatterns = format_suffix_patterns(urlpatterns)
