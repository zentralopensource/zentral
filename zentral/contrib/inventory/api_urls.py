from django.urls import path
from rest_framework.urlpatterns import format_suffix_patterns
from .api_views import (ArchiveMachines,
                        MachinesExport, MacOSAppsExport,
                        MachineMacOSAppInstancesExport,
                        MachineAndroidAppsExport,
                        MachineDebPackagesExport,
                        MachineIOSAppsExport,
                        MachineProgramInstancesExport,
                        MachineSnapshotsExport,
                        MetaBusinessUnitDetail, MetaBusinessUnitList,
                        PruneMachines,
                        TagDetail, TagList, UpdateMachineTags)


app_name = "inventory_api"
urlpatterns = [
    # machine mass tagging
    path('machines/tags/', UpdateMachineTags.as_view(), name="update_machine_tags"),

    # archive or prune machines
    path('machines/archive/', ArchiveMachines.as_view(), name="archive_machines"),
    path('machines/prune/', PruneMachines.as_view(), name="prune_machines"),

    # machine and apps reports
    path('machines/export/', MachinesExport.as_view(), name="machines_export"),
    path('macos_apps/export/', MacOSAppsExport.as_view(), name="macos_apps_export"),

    # machine apps, debs, and programs exports
    path('machines/export_android_apps/',
         MachineAndroidAppsExport.as_view(),
         name="machine_android_apps_export"),
    path('machines/export_deb_packages/',
         MachineDebPackagesExport.as_view(),
         name="machine_deb_packages_export"),
    path('machines/export_ios_apps/',
         MachineIOSAppsExport.as_view(),
         name="machine_ios_apps_export"),
    path('machines/export_macos_app_instances/',
         MachineMacOSAppInstancesExport.as_view(),
         name="machine_macos_app_instances_export"),
    path('machines/export_program_instances/',
         MachineProgramInstancesExport.as_view(),
         name="machine_program_instances_export"),
    path('machines/export_snapshots/',
         MachineSnapshotsExport.as_view(),
         name="machine_snapshots_export"),

    # standard DRF views
    path('meta_business_units/', MetaBusinessUnitList.as_view(), name="meta_business_units"),
    path('meta_business_units/<int:pk>/', MetaBusinessUnitDetail.as_view(), name="meta_business_unit"),
    path('tags/', TagList.as_view(), name="tags"),
    path('tags/<int:pk>/', TagDetail.as_view(), name="tag"),
]


urlpatterns = format_suffix_patterns(urlpatterns)
