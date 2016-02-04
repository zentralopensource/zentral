from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^$', views.IndexView.as_view(), name='index'),
    url(r'^groups/$', views.GroupsView.as_view(), name='groups'),
    url(r'^groups/(?P<group_id>\d+)/machines/$', views.GroupMachinesView.as_view(), name='group_machines'),
    url(r'^business_units/$', views.BUView.as_view(), name='bu'),
    url(r'^business_units/create/$', views.CreateBUView.as_view(), name='create_bu'),
    url(r'^business_units/(?P<pk>\d+)/update/$', views.UpdateBUView.as_view(), name='update_bu'),
    url(r'^business_units/(?P<bu_id>\d+)/machines/$', views.BUMachinesView.as_view(), name='bu_machines'),
    url(r'^machine/(?P<serial_number>\S+)/events/$', views.MachineEventsView.as_view(), name='machine_events'),
    url(r'^machine/(?P<serial_number>\S+)/$', views.MachineView.as_view(), name='machine'),
    url(r'^probes/$', views.ProbesView.as_view(), name='probes'),
    url(r'^probes/(?P<probe_key>[\S ]+)/$', views.ProbeView.as_view(), name='probe'),
]
