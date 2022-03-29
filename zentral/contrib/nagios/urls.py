from django.urls import path
from django.views.decorators.csrf import csrf_exempt
from . import views

app_name = "nagios"
urlpatterns = [
    # setup > nagios instances
    path('instances/', views.NagiosInstancesView.as_view(), name="nagios_instances"),
    path('instances/create/', views.CreateNagiosInstanceView.as_view(), name="create_nagios_instance"),
    path('instances/<int:pk>/download_event_handler/',
         views.DownloadNagiosInstanceEventHandlerView.as_view(),
         name="download_nagios_instance_event_handler"),
    path('instances/<int:pk>/update/', views.UpdateNagiosInstanceView.as_view(), name="update_nagios_instance"),
    path('instances/<int:pk>/delete/', views.DeleteNagiosInstanceView.as_view(), name="delete_nagios_instance"),
    # API
    path('post_event/', csrf_exempt(views.PostEventView.as_view()), name='post_event'),
]


setup_menu_cfg = {
    'items': (
        ('nagios_instances', 'nagios instances'),
    )
}
