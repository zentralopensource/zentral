from django.urls import path
from .api_views import RealmDetail, RealmList


app_name = "realms_api"
urlpatterns = [
    path('realms/', RealmList.as_view(), name="realms"),
    path('realms/<uuid:pk>/', RealmDetail.as_view(), name="realm"),
]
