from django.conf.urls import url
from django.views.decorators.csrf import csrf_exempt
from . import views

app_name = "puppet"
urlpatterns = [
    # setup > puppet instances
    url(r'instances/$', views.InstancesView.as_view(), name="instances"),
    # API
    url(r'^post_report/(?P<secret>\S+)/$', csrf_exempt(views.PostReportView.as_view()), name='post_report'),
]


setup_menu_cfg = {
    'items': (
        ('instances', 'puppet instances'),
    )
}
