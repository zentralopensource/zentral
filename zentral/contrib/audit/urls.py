from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^enrollment/$', views.EnrollmentView.as_view(), name='enrollment'),
    url(r'^installer_package/$', views.InstallerPackageView.as_view(), name='installer_package'),
]


setup_menu_cfg = {
    'items': (
        ('enrollment', 'Enrollment'),
    )
}
