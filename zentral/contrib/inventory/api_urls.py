from django.conf.urls import url
from rest_framework.urlpatterns import format_suffix_patterns
from .api_views import (MachinesExport,
                        MetaBusinessUnitDetail, MetaBusinessUnitList,
                        TagDetail, TagList)


app_name = "inventory_api"
urlpatterns = [
    url('^machines/export/$', MachinesExport.as_view(), name="machines_export"),
    url('^meta_business_units/$', MetaBusinessUnitList.as_view(), name="meta_business_units"),
    url('^meta_business_units/(?P<pk>\d+)/$', MetaBusinessUnitDetail.as_view(), name="meta_business_unit"),
    url('^tags/$', TagList.as_view(), name="tags"),
    url('^tags/(?P<pk>\d+)/$', TagDetail.as_view(), name="tag"),
]


urlpatterns = format_suffix_patterns(urlpatterns)
