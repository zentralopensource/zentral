from django.urls import path
from . import views


app_name = "realms"
urlpatterns = [
    path('', views.RealmListView.as_view(), name='list'),
    path('<slug:backend>/create/', views.CreateRealmView.as_view(), name='create'),
    path('<uuid:pk>/', views.RealmView.as_view(), name='view'),
    path('<uuid:pk>/update/', views.UpdateRealmView.as_view(), name='update'),

    # group mappings
    path('<uuid:pk>/group_mappings/create/',
         views.CreateRealmGroupMappingView.as_view(),
         name='create_group_mapping'),
    path('<uuid:pk>/group_mappings/<uuid:gm_pk>/update/',
         views.UpdateRealmGroupMappingView.as_view(),
         name='update_group_mapping'),
    path('<uuid:pk>/group_mappings/<uuid:gm_pk>/delete/',
         views.DeleteRealmGroupMappingView.as_view(),
         name='delete_group_mapping'),

    # tag mappings
    path('<uuid:pk>/tag_mappings/create/',
         views.CreateRealmTagMappingView.as_view(),
         name='create_tag_mapping'),
    path('<uuid:pk>/tag_mappings/<uuid:tm_pk>/update/',
         views.UpdateRealmTagMappingView.as_view(),
         name='update_tag_mapping'),
    path('<uuid:pk>/tag_mappings/<uuid:tm_pk>/delete/',
         views.DeleteRealmTagMappingView.as_view(),
         name='delete_tag_mapping'),

    # SSO test views
    path('<uuid:pk>/test/', views.TestRealmView.as_view(), name='test'),
    path('<uuid:pk>/sessions/<uuid:ras_pk>/', views.RealmAuthenticationSessionView.as_view(),
         name='authentication_session'),

    # groups
    path('groups/', views.RealmGroupListView.as_view(), name='groups'),
    path('groups/<uuid:pk>/', views.RealmGroupView.as_view(), name='group'),

    # users
    path('users/', views.RealmUserListView.as_view(), name='users'),
    path('users/<uuid:pk>/', views.RealmUserView.as_view(), name='user'),
]
