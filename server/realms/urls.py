from django.urls import path
from . import views
from realms.backends.ldap.urls import urlpatterns as ldap_urlpatterns
from realms.backends.saml.urls import urlpatterns as saml_urlpatterns
from realms.backends.openidc.urls import urlpatterns as openidc_urlpatterns


app_name = "realms"
urlpatterns = [
    path('', views.RealmListView.as_view(), name='list'),
    path('<slug:backend>/create/', views.CreateRealmView.as_view(), name='create'),
    path('<uuid:pk>/', views.RealmView.as_view(), name='view'),
    path('<uuid:pk>/update/', views.UpdateRealmView.as_view(), name='update'),
    path('<uuid:pk>/login/', views.LoginView.as_view(), name='login'),
    path('<uuid:pk>/test/', views.TestRealmView.as_view(), name='test'),
    path('<uuid:pk>/sessions/<uuid:ras_pk>/', views.RealmAuthenticationSessionView.as_view(),
         name='authentication_session'),
]
urlpatterns += ldap_urlpatterns
urlpatterns += saml_urlpatterns
urlpatterns += openidc_urlpatterns


setup_menu_cfg = {
    'items': (
        ('list', 'List'),
    )
}
