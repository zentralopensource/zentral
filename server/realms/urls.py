from django.urls import path
from . import views


app_name = "realms"
urlpatterns = [
    # index
    path('', views.IndexView.as_view(), name='index'),

    # users
    path('users/', views.RealmUserListView.as_view(), name='users'),
    path('users/<uuid:pk>/', views.RealmUserView.as_view(), name='user'),

    # groups
    path('groups/', views.RealmGroupListView.as_view(), name='groups'),
    path('groups/create/', views.CreateRealmGroupView.as_view(), name='create_group'),
    path('groups/<uuid:pk>/', views.RealmGroupView.as_view(), name='group'),
    path('groups/<uuid:pk>/update/', views.UpdateRealmGroupView.as_view(), name='update_group'),
    path('groups/<uuid:pk>/delete/', views.DeleteRealmGroupView.as_view(), name='delete_group'),

    # realm group mappings
    path('group_mappings/',
         views.RealmGroupMappingListView.as_view(),
         name='realm_group_mappings'),
    path('group_mappings/create/',
         views.CreateRealmGroupMappingView.as_view(),
         name='create_realm_group_mapping'),
    path('group_mappings/<uuid:pk>/update/',
         views.UpdateRealmGroupMappingView.as_view(),
         name='update_realm_group_mapping'),
    path('group_mappings/<uuid:pk>/delete/',
         views.DeleteRealmGroupMappingView.as_view(),
         name='delete_realm_group_mapping'),

    # role mappings
    path('role_mappings/',
         views.RoleMappingListView.as_view(),
         name='role_mappings'),
    path('role_mappings/create/',
         views.CreateRoleMappingView.as_view(),
         name='create_role_mapping'),
    path('role_mappings/<uuid:pk>/update/',
         views.UpdateRoleMappingView.as_view(),
         name='update_role_mapping'),
    path('role_mappings/<uuid:pk>/delete/',
         views.DeleteRoleMappingView.as_view(),
         name='delete_role_mapping'),

    # realms
    path('realms/', views.RealmListView.as_view(), name='list'),
    path('realms/<slug:backend>/create/', views.CreateRealmView.as_view(), name='create'),
    path('realms/<uuid:pk>/', views.RealmView.as_view(), name='view'),
    path('realms/<uuid:pk>/update/', views.UpdateRealmView.as_view(), name='update'),

    # SSO test views
    path('realms/<uuid:pk>/test/', views.TestRealmView.as_view(), name='test'),
    path('realms/<uuid:pk>/sessions/<uuid:ras_pk>/', views.RealmAuthenticationSessionView.as_view(),
         name='authentication_session'),
]
