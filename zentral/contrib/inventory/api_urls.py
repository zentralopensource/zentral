from django.conf.urls import url
from rest_framework.urlpatterns import format_suffix_patterns
from .api_views import (MachinesExport, MacOSAppsExport,
                        MachineMacOSAppInstancesExport,
                        MachineProgramInstancesExport,
                        MachineDebPackagesExport,
                        MachineSnapshotsExport,
                        MetaBusinessUnitDetail, MetaBusinessUnitList,
                        TagDetail, TagList, UpdateMachineTags)


app_name = "inventory_api"
urlpatterns = [
    # machine mass tagging
    url('^machines/tags/$', UpdateMachineTags.as_view(), name="update_machine_tags"),

    # machine and apps reports
    url('^machines/export/$', MachinesExport.as_view(), name="machines_export"),
    url('^macos_apps/export/$', MacOSAppsExport.as_view(), name="macos_apps_export"),

    # machine apps, debs, and programs exports
    url('^machines/export_macos_app_instances/$',
        MachineMacOSAppInstancesExport.as_view(),
        name="machine_macos_app_instances_export"),
    url('^machines/export_deb_packages/$',
        MachineDebPackagesExport.as_view(),
        name="machine_deb_packages_export"),
    url('^machines/export_program_instances/$',
        MachineProgramInstancesExport.as_view(),
        name="machine_program_instances_export"),
    url('^machines/export_snapshots/$',
        MachineSnapshotsExport.as_view(),
        name="machine_snapshots_export"),

    # standard DRF views
    url('^meta_business_units/$', MetaBusinessUnitList.as_view(), name="meta_business_units"),
    url(r'^meta_business_units/(?P<pk>\d+)/$', MetaBusinessUnitDetail.as_view(), name="meta_business_unit"),
    url('^tags/$', TagList.as_view(), name="tags"),
    url(r'^tags/(?P<pk>\d+)/$', TagDetail.as_view(), name="tag"),
]


urlpatterns = format_suffix_patterns(urlpatterns)
