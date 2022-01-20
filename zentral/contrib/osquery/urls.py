from django.urls import path
from django.views.decorators.csrf import csrf_exempt
from . import views

app_name = "osquery"
urlpatterns = [
    # index
    path('', views.IndexView.as_view(), name="index"),

    # configurations
    path('configurations/', views.ConfigurationListView.as_view(), name="configurations"),
    path('configurations/create/', views.CreateConfigurationView.as_view(), name='create_configuration'),
    path('configurations/<int:pk>/', views.ConfigurationView.as_view(), name='configuration'),
    path('configurations/<int:pk>/update/', views.UpdateConfigurationView.as_view(), name='update_configuration'),
    path('configurations/<int:pk>/packs/add/',
         views.AddConfigurationPackView.as_view(),
         name='add_configuration_pack'),
    path('configurations/<int:pk>/packs/<int:cp_pk>/update/',
         views.UpdateConfigurationPackView.as_view(),
         name='update_configuration_pack'),
    path('configurations/<int:pk>/packs/<int:cp_pk>/remove/',
         views.RemoveConfigurationPackView.as_view(),
         name='remove_configuration_pack'),

    # file categories
    path('file_categories/', views.FileCategoryListView.as_view(), name="file_categories"),
    path('file_categories/create/', views.CreateFileCategoryView.as_view(), name="create_file_category"),
    path('file_categories/<int:pk>/', views.FileCategoryView.as_view(), name="file_category"),
    path('file_categories/<int:pk>/update/', views.UpdateFileCategoryView.as_view(), name="update_file_category"),
    path('file_categories/<int:pk>/delete/', views.DeleteFileCategoryView.as_view(), name="delete_file_category"),

    # automatic table constructions
    path('atcs/', views.ATCListView.as_view(), name="atcs"),
    path('atcs/create/', views.CreateATCView.as_view(), name="create_atc"),
    path('atcs/<int:pk>/', views.ATCView.as_view(), name="atc"),
    path('atcs/<int:pk>/update/', views.UpdateATCView.as_view(), name="update_atc"),
    path('atcs/<int:pk>/delete/', views.DeleteATCView.as_view(), name="delete_atc"),

    # packs
    path('packs/', views.PackListView.as_view(), name="packs"),
    path('packs/create/', views.CreatePackView.as_view(), name="create_pack"),
    path('packs/<int:pk>/', views.PackView.as_view(), name="pack"),
    path('packs/<int:pk>/update/', views.UpdatePackView.as_view(), name="update_pack"),
    path('packs/<int:pk>/delete/', views.DeletePackView.as_view(), name="delete_pack"),
    path('packs/<int:pk>/queries/add/', views.AddPackQueryView.as_view(), name="add_pack_query"),
    path('packs/<int:pk>/queries/<int:pq_pk>/update/', views.UpdatePackQueryView.as_view(), name="update_pack_query"),
    path('packs/<int:pk>/queries/<int:pq_pk>/delete/', views.DeletePackQueryView.as_view(), name="delete_pack_query"),

    # queries
    path('queries/', views.QueryListView.as_view(), name="queries"),
    path('queries/create/', views.CreateQueryView.as_view(), name="create_query"),
    path('queries/<int:pk>/', views.QueryView.as_view(), name="query"),
    path('queries/<int:pk>/update/', views.UpdateQueryView.as_view(), name="update_query"),
    path('queries/<int:pk>/delete/', views.DeleteQueryView.as_view(), name="delete_query"),

    # distributed queries
    path('runs/', views.DistributedQueryListView.as_view(), name="distributed_queries"),
    path('runs/launch/', views.CreateDistributedQueryView.as_view(), name="create_distributed_query"),
    path('runs/<int:pk>/', views.DistributedQueryView.as_view(), name="distributed_query"),
    path('runs/<int:pk>/update/', views.UpdateDistributedQueryView.as_view(), name="update_distributed_query"),
    path('runs/<int:pk>/delete/', views.DeleteDistributedQueryView.as_view(), name="delete_distributed_query"),
    path('runs/<int:pk>/machines/', views.DistributedQueryMachineListView.as_view(),
         name="distributed_query_machines"),
    path('runs/<int:pk>/results/', views.DistributedQueryResultListView.as_view(),
         name="distributed_query_results"),
    path('runs/<int:pk>/file_carving_sessions/', views.DistributedQueryFileCarvingSessionListView.as_view(),
         name="distributed_query_file_carving_sessions"),

    # file carving session
    path('file_carving_sessions/<uuid:pk>/download/', views.DownloadFileCarvingSessionArchiveView.as_view(),
         name="download_file_carving_session_archive"),

    # enrollment
    path('configurations/<int:pk>/enrollments/create/',
         views.CreateEnrollmentView.as_view(),
         name='create_enrollment'),
    path('configurations/<int:configuration_pk>/enrollments/<int:pk>/delete/',
         views.DeleteEnrollmentView.as_view(),
         name='delete_enrollment'),
    path('configurations/<int:configuration_pk>/enrollments/<int:pk>/bump_version/',
         views.EnrollmentBumpVersionView.as_view(),
         name='bump_enrollment_version'),

    # osquery API
    path('enroll', csrf_exempt(views.EnrollView.as_view()), name='enroll'),
    path('config', csrf_exempt(views.ConfigView.as_view()), name='config'),
    path('carver/start', csrf_exempt(views.StartFileCarvingView.as_view()), name='carver_start'),
    path('carver/continue', csrf_exempt(views.ContinueFileCarvingView.as_view()), name='carver_continue'),
    path('distributed/read', csrf_exempt(views.DistributedReadView.as_view()), name='distributed_read'),
    path('distributed/write', csrf_exempt(views.DistributedWriteView.as_view()), name='distributed_write'),
    path('log', csrf_exempt(views.LogView.as_view()), name='log'),
]


setup_menu_cfg = {
    'items': (
        ('index', 'Overview', False, ('osquery',)),
        ('packs', 'Packs', False, ('osquery.view_pack',)),
        ('queries', 'Queries', False, ('osquery.view_query',)),
        ('distributed_queries', 'Runs', False, ('osquery.view_distributedquery',)),
        ('configurations', 'Configurations', False, ('osquery.view_configuration',)),
        ('atcs', 'ATCs', False, ('osquery.view_automatictableconstruction',)),
        ('file_categories', 'File categories', False, ('osquery.view_filecategory',)),
    )
}
