from django.urls import path
from . import public_views
from realms.backends.ldap.public_urls import urlpatterns as ldap_urlpatterns
from realms.backends.saml.public_urls import urlpatterns as saml_urlpatterns
from realms.backends.openidc.public_urls import urlpatterns as openidc_urlpatterns
from . import scim_views


app_name = "realms_public"
urlpatterns = [
    # SSO login
    path('<uuid:pk>/login/', public_views.LoginView.as_view(), name='login'),

    # SCIM
    path('<uuid:realm_pk>/scim/v2/Groups', scim_views.GroupsView.as_view(), name='scim_groups'),
    path('<uuid:realm_pk>/scim/v2/Groups/<uuid:pk>', scim_views.GroupView.as_view(), name='scim_group'),
    path('<uuid:realm_pk>/scim/v2/ResourceTypes', scim_views.ResourceTypesView.as_view(), name='scim_resource_types'),
    path('<uuid:realm_pk>/scim/v2/ResourceTypes/urn:ietf:params:scim:schemas:core:2.0:<slug:resource_type>',
         scim_views.ResourceTypeView.as_view(), name='scim_resource_type'),
    path('<uuid:realm_pk>/scim/v2/Schemas', scim_views.SchemasView.as_view(), name='scim_schemas'),
    path('<uuid:realm_pk>/scim/v2/ServiceProviderConfig', scim_views.ServiceProviderConfigView.as_view(),
         name='scim_sp_config'),
    path('<uuid:realm_pk>/scim/v2/Users', scim_views.UsersView.as_view(), name='scim_users'),
    path('<uuid:realm_pk>/scim/v2/Users/<uuid:pk>', scim_views.UserView.as_view(), name='scim_user'),
]
urlpatterns += ldap_urlpatterns
urlpatterns += saml_urlpatterns
urlpatterns += openidc_urlpatterns
