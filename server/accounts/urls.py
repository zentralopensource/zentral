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
    path('users/<signed_pk>/view_api_token/', views.UserAPITokenView.as_view(),
         name="user_api_token"),
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
    path('settings/verification_devices/', views.UserVerificationDevicesView.as_view(),
         name="verification_devices"),
    path('settings/verification_devices/add_totp/', views.AddTOTPView.as_view(),
         name="add_totp"),
    path('settings/verification_devices/totp/<int:pk>/delete/', views.DeleteTOTPView.as_view(),
         name="delete_totp"),
    path('verify_totp/', views.VerifyTOTPView.as_view(),
         name='verify_totp'),
    path('settings/verification_devices/register_u2f_device/', views.RegisterU2FDeviceView.as_view(),
         name="register_u2f_device"),
    path('settings/verification_devices/u2f/<int:pk>/delete/', views.DeleteU2FDeviceView.as_view(),
         name="delete_u2f_device"),
    path(r'verify_u2f/', views.VerifyU2FView.as_view(),
         name='verify_u2f'),
]

setup_menu_cfg = {
    'weight': 1,
    'items': (
        ('users', 'Users', False, ('accounts.view_user',)),
        ('groups', 'Groups', False, ('auth.view_group',)),
    )
}
