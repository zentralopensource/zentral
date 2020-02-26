from django.urls import path
from . import views

urlpatterns = [
    path('<uuid:uuid>/openidc/ac_redirect/',
         views.AuthorizationCodeFlowRedirectView.as_view(),
         name="openidc_ac_redirect"),
]
