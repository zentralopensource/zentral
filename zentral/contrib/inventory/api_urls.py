from django.conf.urls import url
from rest_framework.urlpatterns import format_suffix_patterns
from .api_views import MetaBusinessUnitDetail, MetaBusinessUnitList


urlpatterns = [
    url('^meta_business_units/$', MetaBusinessUnitList.as_view(), name="meta_business_units"),
    url('^meta_business_units/(?P<pk>\d+)/$', MetaBusinessUnitDetail.as_view(), name="meta_business_unit"),
]


urlpatterns = format_suffix_patterns(urlpatterns)
