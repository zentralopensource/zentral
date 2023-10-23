from django.urls import path
from django.views.decorators.csrf import csrf_exempt
from . import views

app_name = "jamf"
urlpatterns = [
    # setup > jamf instances
    path('instances/', views.JamfInstancesView.as_view(), name="jamf_instances"),
    path('instances/create/', views.CreateJamfInstanceView.as_view(), name="create_jamf_instance"),
    path('instances/<int:pk>/', views.JamfInstanceView.as_view(), name="jamf_instance"),
    path('instances/<int:pk>/setup/', views.SetupJamfInstanceView.as_view(), name="setup_jamf_instance"),
    path('instances/<int:pk>/update/', views.UpdateJamfInstanceView.as_view(), name="update_jamf_instance"),
    path('instances/<int:pk>/delete/', views.DeleteJamfInstanceView.as_view(), name="delete_jamf_instance"),
    path('instances/<int:pk>/tag_configs/create/',
         views.CreateTagConfigView.as_view(),
         name="create_tag_config"),
    path('instances/<int:ji_pk>/tag_configs/<int:pk>/update/',
         views.UpdateTagConfigView.as_view(),
         name="update_tag_config"),
    path('instances/<int:ji_pk>/tag_configs/<int:pk>/delete/',
         views.DeleteTagConfigView.as_view(),
         name="delete_tag_config"),
    # API
    path('post_event/<slug:secret>/', csrf_exempt(views.PostEventView.as_view()), name='post_event'),
]


modules_menu_cfg = {
    'items': (
        ('jamf_instances', 'jamf instances', False, ('jamf.view_jamfinstance',)),
    ),
    'weight': 60,
}
