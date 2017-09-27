from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^$', views.UsersView.as_view(),
        name="list"),
    url(r'^nginx/auth_request/$', views.NginxAuthRequestView.as_view(),
        name="nginx_auth_request"),
    url(r'^add/$', views.AddUserView.as_view(),
        name="add"),
    url(r'^(?P<pk>[0-9]+)/update/$', views.UpdateUserView.as_view(),
        name="update"),
    url(r'^(?P<pk>[0-9]+)/delete/$', views.DeleteUserView.as_view(),
        name="delete"),
    url(r'^verification_devices/$', views.UserVerificationDevicesView.as_view(),
        name="verification_devices"),
    url(r'^add_totp/$', views.AddTOTPView.as_view(),
        name="add_totp"),
    url(r'^totp/(?P<pk>[0-9]+)/delete/$', views.DeleteTOTPView.as_view(),
        name="delete_totp"),
]
