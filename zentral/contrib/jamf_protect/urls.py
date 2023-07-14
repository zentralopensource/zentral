from django.urls import path
from django.views.decorators.csrf import csrf_exempt
from . import views

app_name = "jamf_protect"
urlpatterns = [
    # setup > Jamf Protect enrollments
    path('enrollments/', views.EnrollmentsView.as_view(), name="enrollments"),
    path('enrollments/create/', views.CreateEnrollmentView.as_view(), name="create_enrollment"),
    # Jamf Protect API
    path('events/', csrf_exempt(views.PostEventView.as_view()), name='events'),
]


modules_menu_cfg = {
    'title': 'Jamf Protect',
    'items': (
        ('enrollments', 'Enrollments'),
    )
}
