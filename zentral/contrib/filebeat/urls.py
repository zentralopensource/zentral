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
    # path('configurations/<int:configuration_pk>/enrollments/<int:pk>/',
    #      views.EnrollmentPackageView.as_view(),
    #      name='enrollment_package'),
    # enrollment endpoint called by enrollment script
    path('enroll/', csrf_exempt(views.EnrollView.as_view()),
         name='enroll'),
]


setup_menu_cfg = {
    'items': (
        ('configuration_list', 'Configurations'),
    )
}
