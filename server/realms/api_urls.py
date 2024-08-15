from django.urls import path
from rest_framework.urlpatterns import format_suffix_patterns
from .api_views import RealmDetail, RealmList


app_name = "realms_api"
urlpatterns = [
    path('realms/', RealmList.as_view(), name="realms"),
    path('realms/<uuid:pk>/', RealmDetail.as_view(), name="realm"),
]


urlpatterns = format_suffix_patterns(urlpatterns)
