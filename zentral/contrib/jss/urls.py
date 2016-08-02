from django.conf.urls import url
from django.views.decorators.csrf import csrf_exempt
from . import views

urlpatterns = [
    url(r'enrollment/$', views.EnrollmentView.as_view(), name="enrollment"),
    url(r'enrollment/debugging/$',
        views.EnrollmentDebuggingView.as_view(), name="enrollment_debugging"),
    # API
    url(r'^post_event/(?P<api_secret>\S+)/$', csrf_exempt(views.PostEventView.as_view()), name='post_event'),
]


main_menu_cfg = {
    'items': (
        ('enrollment', 'Enrollment'),
    )
}
