from django.urls import path

from . import views

app_name = "users"
urlpatterns = [
    path('', views.UsersView.as_view(),
         name="list"),
    path('nginx/auth_request/', views.NginxAuthRequestView.as_view(),
         name="nginx_auth_request"),
    path('add/', views.AddUserView.as_view(),
         name="add"),
    path('<int:pk>/update/', views.UpdateUserView.as_view(),
         name="update"),
    path('<int:pk>/delete/', views.DeleteUserView.as_view(),
         name="delete"),
    path('verification_devices/', views.UserVerificationDevicesView.as_view(),
         name="verification_devices"),
    path('add_totp/', views.AddTOTPView.as_view(),
         name="add_totp"),
    path('totp/<int:pk>/delete/', views.DeleteTOTPView.as_view(),
         name="delete_totp"),
    path('u2f_devices/register/', views.RegisterU2FDeviceView.as_view(),
         name="register_u2f_device"),
    path('u2f_devices/<int:pk>/delete/', views.DeleteU2FDeviceView.as_view(),
         name="delete_u2f_device"),
]
