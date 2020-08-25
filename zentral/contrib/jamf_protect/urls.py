from django.conf.urls import url
from django.views.decorators.csrf import csrf_exempt
from . import views

app_name = "jamf_protect"
urlpatterns = [
    # setup > Jamf Protect enrollments
    url(r'enrollments/$', views.EnrollmentsView.as_view(), name="enrollments"),
    url(r'enrollments/create/$', views.CreateEnrollmentView.as_view(), name="create_enrollment"),
    # Jamf Protect API
    url(r'^events/$', csrf_exempt(views.PostEventView.as_view()), name='events'),
]


setup_menu_cfg = {
    'title': 'Jamf Protect',
    'items': (
        ('enrollments', 'Enrollments'),
    )
}
