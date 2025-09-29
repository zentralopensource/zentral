from django.urls import path
from django.views.decorators.csrf import csrf_exempt
from . import public_views

app_name = "mdm_public"
urlpatterns = [
    # Apps & Books / apps views
    path('locations/<uuid:mdm_info_id>/notify/',
         csrf_exempt(public_views.NotifyLocationView.as_view()),
         name='notify_location'),

    # DEP enrollment / dep views
    path('dep_enroll/<str:dep_enrollment_secret>/',
         csrf_exempt(public_views.DEPEnrollView.as_view()),
         name='dep_enroll'),
    path('dep_web_enroll/<str:dep_enrollment_secret>/',
         public_views.DEPWebEnrollView.as_view(),
         name='dep_web_enroll'),
    path('dep_web_enroll/<str:dep_enrollment_secret>/custom_views/<uuid:pk>/',
         csrf_exempt(public_views.DEPWebEnrollCustomView.as_view()),
         name='dep_web_enroll_custom_view'),
    path('dep_web_enroll/<str:dep_enrollment_secret>/profile/',
         public_views.DEPWebEnrollProfileView.as_view(),
         name='dep_web_enroll_profile'),

    # MDM protocol / mdm views
    path('checkin/',
         csrf_exempt(public_views.CheckinView.as_view()),
         name='checkin'),
    path('connect/',
         csrf_exempt(public_views.ConnectView.as_view()),
         name='connect'),

    # Download views
    path('acme_credential/<str:token>/',
         public_views.ACMECredentialView.as_view(),
         name="acme_credential"),
    path('scep_credential/<str:token>/',
         public_views.SCEPCredentialView.as_view(),
         name="scep_credential"),
    path('data_assets/<str:token>/',
         public_views.DataAssetDownloadView.as_view(),
         name="data_asset_download_view"),
    path('profiles/<str:token>/',
         public_views.ProfileDownloadView.as_view(),
         name="profile_download_view"),
    path('device_commands/<uuid:uuid>/enterprise_app/',
         public_views.EnterpriseAppDownloadView.as_view(),
         name="enterprise_app_download"),

    # OTA enrollment / ota views
    path('ota_enrollment/<int:pk>/enroll/',
         public_views.OTAEnrollmentEnrollView.as_view(),
         name='ota_enrollment_enroll'),
    path('ota_enroll/',
         csrf_exempt(public_views.OTAEnrollView.as_view()),
         kwargs={"session": False},
         name='ota_enroll'),
    path('ota_session_enroll/',
         csrf_exempt(public_views.OTAEnrollView.as_view()),
         kwargs={"session": True},
         name='ota_session_enroll'),

    # User enrollment / user views
    path('user_enrollment/<str:secret>/com.apple.remotemanagement/',
         csrf_exempt(public_views.UserEnrollmentServiceDiscoveryView.as_view()),
         name='user_enrollment_service_discovery'),
    path('user_enrollment/<str:secret>/enroll/',
         csrf_exempt(public_views.EnrollUserView.as_view()),
         name='enroll_user'),
    path('user_enrollment_session/<str:secret>/authenticate/',
         csrf_exempt(public_views.AuthenticateUserView.as_view()),
         name='authenticate_user'),
]
