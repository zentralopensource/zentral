from django.conf.urls import url
from django.views.decorators.csrf import csrf_exempt
from . import views

urlpatterns = [
    # django admin
    url(r'^$', views.IndexView.as_view(), name='index'),
    url(r'^probes/(?P<probe_key>[\S ]+)/$', views.ProbeView.as_view(), name='probe'),
    # django admin distributed queries
    url(r'^distributed/$',
        csrf_exempt(views.DistributedIndexView.as_view()),
        name='distributed_index'),
    url(r'^distributed/create/$',
        csrf_exempt(views.CreateDistributedView.as_view()),
        name='distributed_create'),
    url(r'^distributed/(?P<pk>\d+)/$',
        csrf_exempt(views.DistributedView.as_view()),
        name='distributed'),
    url(r'^distributed/(?P<pk>\d+)/update/$',
        csrf_exempt(views.UpdateDistributedView.as_view()),
        name='distributed_update'),
    url(r'^distributed/(?P<pk>\d+)/delete/$',
        csrf_exempt(views.DeleteDistributedView.as_view()),
        name='distributed_delete'),
    url(r'^distributed/(?P<pk>\d+)/download/$',
        csrf_exempt(views.DownloadDistributedView.as_view()),
        name='distributed_download'),
    # API
    url(r'^enroll$', csrf_exempt(views.EnrollView.as_view()), name='enroll'),
    url(r'^config$', csrf_exempt(views.ConfigView.as_view()), name='config'),
    url(r'^distributed/read$', csrf_exempt(views.DistributedReadView.as_view()), name='distributed_read'),
    url(r'^distributed/write$', csrf_exempt(views.DistributedWriteView.as_view()), name='distributed_write'),
    url(r'^log$', csrf_exempt(views.LogView.as_view()), name='log'),
]
