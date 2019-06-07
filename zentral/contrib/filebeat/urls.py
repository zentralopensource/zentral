from django.urls import path
from django.views.decorators.csrf import csrf_exempt
from . import views

app_name = "filebeat"
urlpatterns = [
    # configuration / enrollment
    path('configurations/',
         views.ConfigurationListView.as_view(),
         name='configuration_list'),
    path('configurations/create/',
         views.CreateConfigurationView.as_view(),
         name='create_configuration'),
    path('configurations/<int:pk>/',
         views.ConfigurationView.as_view(),
         name='configuration'),
    path('configurations/<int:pk>/update/',
         views.UpdateConfigurationView.as_view(),
         name='update_configuration'),
    path('configurations/<int:pk>/enrollments/create/',
         views.CreateEnrollmentView.as_view(),
         name='create_enrollment'),
    path('configurations/<int:configuration_pk>/enrollments/<int:pk>/package/',
         views.EnrollmentPackageView.as_view(),
         name='enrollment_package'),
    path('configurations/<int:configuration_pk>/enrollments/<int:pk>/script/',
         views.EnrollmentScriptView.as_view(),
         name='enrollment_script'),

    # enrollment endpoints called by enrollment script
    path('enrollment/start/', csrf_exempt(views.StartEnrollmentView.as_view()),
         name='start_enrollment'),
    path('enrollment/complete/', csrf_exempt(views.CompleteEnrollmentView.as_view()),
         name='complete_enrollment'),
    # SCEP verification / scep view
    path('verify_scep_csr/',
         csrf_exempt(views.VerifySCEPCSRView.as_view()),
         name='verify_scep_csr'),

]


setup_menu_cfg = {
    'items': (
        ('configuration_list', 'Configurations'),
    )
}
