from django.urls import path
from . import views

app_name = "google_workspace"
urlpatterns = [
    path('', views.IndexView.as_view(), name="index"),
    path('connections/', views.ConnectionsView.as_view(), name="connections"),
    path('connections/create/', views.CreateConnectionView.as_view(), name="create_connection"),
    path('connections/redirect/', views.ConnectionRedirectView.as_view(), name="redirect"),
    path('connections/<uuid:pk>/', views.ConnectionView.as_view(), name="connection"),
    path('connections/<uuid:pk>/authorize/', views.AuthorizeConnectionView.as_view(), name="authorize_connection"),
    path('connections/<uuid:pk>/update/', views.UpdateConnectionView.as_view(), name="update_connection"),
    path('connections/<uuid:pk>/delete/', views.DeleteConnectionView.as_view(), name="delete_connection"),
    path('connections/<uuid:conn_pk>/group_tag_mappings/create/',
         views.CreateGroupTagMappingView.as_view(), name="create_group_tag_mapping"),
    path('connections/<uuid:conn_pk>/group_tag_mappings/<uuid:pk>/update/',
         views.UpdateGroupTagMappingView.as_view(), name="update_group_tag_mapping"),
    path('connections/<uuid:conn_pk>/group_tag_mappings/<uuid:pk>/delete/',
         views.DeleteGroupTagMappingView.as_view(), name="delete_group_tag_mapping"),
]

modules_menu_cfg = {
    'items': (
        ('index', 'Overview', False, ('google_workspace',)),
        ('connections', 'Connections', False, ('google_workspace.view_connection',)),
    ),
    'weight': 70,
}
