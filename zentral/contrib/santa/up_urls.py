from django.urls import path, re_path
from . import up_views

app_name = "santa_up"
urlpatterns = [
    path("event_detail/",
         up_views.EventDetailView.as_view(), name="event_detail"),
    re_path("^targets/(?P<type>bundle|binary)/(?P<identifier>[^/]+)/",
            up_views.TargetDetailView.as_view(), name="target"),
]
