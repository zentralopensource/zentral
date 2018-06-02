from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^installer/$', views.InstallerView.as_view(), name='installer'),
]


setup_menu_cfg = {
    'items': (
        ('installer', 'Installer'),
    )
}
