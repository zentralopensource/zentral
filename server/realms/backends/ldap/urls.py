from django.urls import path
from . import views

urlpatterns = [
    path('<uuid:uuid>/ldap/<uuid:session_pk>/login/',
         views.LoginView.as_view(),
         name="ldap_login"),
]
