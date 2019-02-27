from django.conf.urls import url
from . import views

app_name = "audit"
urlpatterns = [
    url(r'^installer/$', views.InstallerView.as_view(), name='installer'),
]


setup_menu_cfg = {
    'items': (
        ('installer', 'Installer'),
    )
}
