from django.conf.urls import url
from django.views.decorators.csrf import csrf_exempt
from . import views

urlpatterns = [
    # setup
    url(r'^enrollment/$', views.EnrollmentView.as_view(), name='enrollment'),
    url(r'^enrollment/debugging/$',
        views.EnrollmentDebuggingView.as_view(), name='enrollment_debugging'),
    url(r'^installer_package/$', views.InstallerPackageView.as_view(), name='installer_package'),
    url(r'^setup_script/$', views.SetupScriptView.as_view(), name='setup_script'),
    # osquery probes
    url(r'^probes/create/$', views.CreateProbeView.as_view(), name='create_probe'),
    # osquery probe discovery
    url(r'^probes/(?P<probe_id>\d+)/discovery/add/$',
        views.AddProbeDiscoveryView.as_view(), name='add_probe_discovery'),
    url(r'^probes/(?P<probe_id>\d+)/discovery/(?P<discovery_id>\d+)/update/$',
        views.UpdateProbeDiscoveryView.as_view(), name='update_probe_discovery'),
    url(r'^probes/(?P<probe_id>\d+)/discovery/(?P<discovery_id>\d+)/delete/$',
        views.DeleteProbeDiscoveryView.as_view(), name='delete_probe_discovery'),
    # osquery probes query
    url(r'^probes/(?P<probe_id>\d+)/queries/add/$',
        views.AddProbeQueryView.as_view(), name='add_probe_query'),
    url(r'^probes/(?P<probe_id>\d+)/queries/(?P<query_id>\d+)/update/$',
        views.UpdateProbeQueryView.as_view(), name='update_probe_query'),
    url(r'^probes/(?P<probe_id>\d+)/queries/(?P<query_id>\d+)/delete/$',
        views.DeleteProbeQueryView.as_view(), name='delete_probe_query'),
    # osquery compliance probes
    url(r'^compliance_probes/create/$',
        views.CreateComplianceProbeView.as_view(), name='create_compliance_probe'),
    # osquery compliance probes preference files
    url(r'^compliance_probes/(?P<probe_id>\d+)/preference_files/add/$',
        views.AddComplianceProbePreferenceFileView.as_view(), name='add_compliance_probe_preference_file'),
    url(r'^compliance_probes/(?P<probe_id>\d+)/preference_files/(?P<pf_id>\d+)/update/$',
        views.UpdateComplianceProbePreferenceFileView.as_view(), name='update_compliance_probe_preference_file'),
    url(r'^compliance_probes/(?P<probe_id>\d+)/preference_files/(?P<pf_id>\d+)/delete/$',
        views.DeleteComplianceProbePreferenceFileView.as_view(), name='delete_compliance_probe_preference_file'),
    # osquery compliance probes file checksums
    url(r'^compliance_probes/(?P<probe_id>\d+)/file_checksums/add/$',
        views.AddComplianceProbeFileChecksumView.as_view(), name='add_compliance_probe_file_checksum'),
    url(r'^compliance_probes/(?P<probe_id>\d+)/file_checksums/(?P<fc_id>\d+)/update/$',
        views.UpdateComplianceProbeFileChecksumView.as_view(), name='update_compliance_probe_file_checksum'),
    url(r'^compliance_probes/(?P<probe_id>\d+)/file_checksums/(?P<fc_id>\d+)/delete/$',
        views.DeleteComplianceProbeFileChecksumView.as_view(), name='delete_compliance_probe_file_checksum'),
    # osquery distributed query probes
    url(r'^distributed_query_probes/create/$',
        views.CreateDistributedQueryProbeView.as_view(), name='create_distributed_query_probe'),
    url(r'^distributed_query_probes/(?P<probe_id>\d+)/update_query/$',
        views.UpdateDistributedQueryProbeQueryView.as_view(), name='update_distributed_query_probe_query'),
    # osquery file carve probes
    url(r'^file_carve_probes/create/$',
        views.CreateFileCarveProbeView.as_view(), name='create_file_carve_probe'),
    url(r'^file_carve_probes/(?P<probe_id>\d+)/update_path/$',
        views.UpdateFileCarveProbePathView.as_view(), name='update_file_carve_probe_path'),
    url(r'^file_carve_probes/(?P<probe_id>\d+)/sessions/$',
        views.FileCarveProbeSessionsView.as_view(), name='file_carve_probe_sessions'),
    url(r'^file_carve_sessions/(?P<session_id>\d+)/archive/$',
        views.DownloadFileCarveSessionArchiveView.as_view(), name='download_file_carve_session_archive'),
    # osquery fim probes
    url(r'fim_probes/create/$',
        views.CreateFIMProbeView.as_view(), name='create_fim_probe'),
    # osquery fim probes file paths
    url(r'fim_probes/(?P<probe_id>\d+)/file_paths/add/$',
        views.AddFIMProbeFilePathView.as_view(), name='add_fim_probe_file_path'),
    url(r'^probes/(?P<probe_id>\d+)/file_paths/(?P<file_path_id>\d+)/update/$',
        views.UpdateFIMProbeFilePathView.as_view(), name='update_fim_probe_file_path'),
    url(r'^probes/(?P<probe_id>\d+)/file_paths/(?P<file_path_id>\d+)/delete/$',
        views.DeleteFIMProbeFilePathView.as_view(), name='delete_fim_probe_file_path'),
    # API
    url(r'^enroll$', csrf_exempt(views.EnrollView.as_view()), name='enroll'),
    url(r'^config$', csrf_exempt(views.ConfigView.as_view()), name='config'),
    url(r'^carver/start$', csrf_exempt(views.CarverStartView.as_view()), name='carver_start'),
    url(r'^carver/continue$', csrf_exempt(views.CarverContinueView.as_view()), name='carver_continue'),
    url(r'^distributed/read$', csrf_exempt(views.DistributedReadView.as_view()), name='distributed_read'),
    url(r'^distributed/write$', csrf_exempt(views.DistributedWriteView.as_view()), name='distributed_write'),
    url(r'^log$', csrf_exempt(views.LogView.as_view()), name='log'),
]


setup_menu_cfg = {
    'items': (
        ('enrollment', 'Enrollment'),
    )
}
