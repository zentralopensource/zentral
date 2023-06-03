from django.urls import path
from . import public_views

urlpatterns = [
    path('<uuid:uuid>/ldap/<uuid:session_pk>/login/',
         public_views.LoginView.as_view(),
         name="ldap_login"),
]
