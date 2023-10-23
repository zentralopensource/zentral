from django.urls import path
from django.views.decorators.csrf import csrf_exempt
from . import views


app_name = "puppet"
urlpatterns = [
    path('', views.IndexView.as_view(), name="index"),

    # instances
    path('instances/', views.InstanceListView.as_view(), name="instances"),
    path('instances/create/', views.CreateInstanceView.as_view(), name="create_instance"),
    path('instances/<int:pk>/', views.InstanceView.as_view(), name="instance"),
    path('instances/<int:pk>/update/', views.UpdateInstanceView.as_view(), name="update_instance"),
    path('instances/<int:pk>/delete/', views.DeleteInstanceView.as_view(), name="delete_instance"),
    path('instances/<int:pk>/events/',
         views.InstanceEventsView.as_view(),
         name='instance_events'),
    path('instances/<int:pk>/events/fetch/',
         views.FetchInstanceEventsView.as_view(),
         name='fetch_instance_events'),
    path('instances/<int:pk>/events/store_redirect/',
         views.InstanceEventsStoreRedirectView.as_view(),
         name='instance_events_store_redirect'),

    # report endpoint
    path('instances/<int:pk>/post_report/',
         csrf_exempt(views.PostReportView.as_view()),
         name="post_report"),
]


modules_menu_cfg = {
    'items': (
        ('index', 'Overview', False, ('puppet',)),
        ('instances', 'Instances', False, ('puppet.view_instance',)),
    )
}
