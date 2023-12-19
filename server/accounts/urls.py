from django.urls import path

from . import views

app_name = "accounts"
urlpatterns = [
    path('nginx/auth_request/', views.NginxAuthRequestView.as_view(),
         name="nginx_auth_request"),

    # manage users
    path('users/', views.UsersView.as_view(),
         name="users"),
    path('users/invite/', views.InviteUserView.as_view(),
         name="invite_user"),
    path('users/create_service_account/', views.CreateServiceAccountView.as_view(),
         name="create_service_account"),
    path('users/<int:pk>/', views.UserView.as_view(),
         name="user"),
    path('users/<int:pk>/update/', views.UpdateUserView.as_view(),
         name="update_user"),
    path('users/<int:pk>/delete/', views.DeleteUserView.as_view(),
         name="delete_user"),
    path('users/<int:pk>/api_token/create/', views.CreateUserAPITokenView.as_view(),
         name="create_user_api_token"),
    path('users/<int:pk>/api_token/delete/', views.DeleteUserAPITokenView.as_view(),
         name="delete_user_api_token"),

    # manage groups
    path('groups/', views.GroupsView.as_view(), name="groups"),
    path('groups/create/', views.CreateGroupView.as_view(), name="create_group"),
    path('groups/<int:pk>/', views.GroupView.as_view(), name="group"),
    path('groups/<int:pk>/update/', views.UpdateGroupView.as_view(), name="update_group"),
    path('groups/<int:pk>/delete/', views.DeleteGroupView.as_view(), name="delete_group"),

    # user views
    path('settings/profile/', views.ProfileView.as_view(), name="profile"),
    path('settings/profile/update/', views.UpdateProfileView.as_view(), name="update_profile"),
    path('settings/verification_devices/', views.UserVerificationDevicesView.as_view(),
         name="verification_devices"),
    path('settings/verification_devices/add_totp/', views.AddTOTPView.as_view(),
         name="add_totp"),
    path('settings/verification_devices/totp/<int:pk>/delete/', views.DeleteTOTPView.as_view(),
         name="delete_totp"),
    path('verify_totp/', views.VerifyTOTPView.as_view(),
         name='verify_totp'),
    path('settings/verification_devices/register_webauthn_device/', views.RegisterWebAuthnDeviceView.as_view(),
         name="register_webauthn_device"),
    path('settings/verification_devices/webauthn/<int:pk>/delete/', views.DeleteWebAuthnDeviceView.as_view(),
         name="delete_webauthn_device"),
    path(r'verify_webauthn/', views.VerifyWebAuthnView.as_view(),
         name='verify_webauthn'),
]
