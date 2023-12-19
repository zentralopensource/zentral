from django.urls import path
from . import views

app_name = "incidents"
urlpatterns = [
    path('', views.IndexView.as_view(), name='index'),
    path('<int:pk>/', views.IncidentView.as_view(), name='incident'),
    path('<int:pk>/update/', views.UpdateIncidentView.as_view(), name='update_incident'),
    path('<int:incident_pk>/machine_incident/<int:pk>/update/',
         views.UpdateMachineIncidentView.as_view(), name='update_machine_incident'),

    # events
    path('<int:pk>/events/',
         views.IncidentEventsView.as_view(), name='incident_events'),
    path('<int:pk>/events/fetch/',
         views.FetchIncidentEventsView.as_view(), name='fetch_incident_events'),
    path('<int:pk>/events/store_redirect/',
         views.IncidentEventsStoreRedirectView.as_view(), name='incident_events_store_redirect'),
]

pinned_menu_cfg = {
    'weight': 2,
    'items': (
        ('index', 'all incidents', False, ("incidents.view_incident",)),
    ),
}
