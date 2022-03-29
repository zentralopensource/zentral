from django.urls import path
from . import views

app_name = "simplemdm"
urlpatterns = [
    path('instances/',
         views.SimpleMDMInstancesView.as_view(),
         name="simplemdm_instances"),
    path('instances/create/',
         views.CreateSimpleMDMInstanceView.as_view(),
         name="create_simplemdm_instance"),
    path('instances/<int:pk>/',
         views.SimpleMDMInstanceView.as_view(),
         name="simplemdm_instance"),
    path('instances/<int:pk>/update/',
         views.UpdateSimpleMDMInstanceView.as_view(),
         name="update_simplemdm_instance"),
    path('instances/<int:pk>/delete/',
         views.DeleteSimpleMDMInstanceView.as_view(),
         name="delete_simplemdm_instance"),
    path('instances/<int:pk>/create_app/',
         views.CreateSimpleMDMAppView.as_view(),
         name="create_simplemdm_app"),
    path('instances/<int:instance_pk>/delete_app/<int:pk>/',
         views.DeleteSimpleMDMAppView.as_view(),
         name="delete_simplemdm_app"),
]


setup_menu_cfg = {
    'items': (
        ('simplemdm_instances', 'Instances'),
    )
}
