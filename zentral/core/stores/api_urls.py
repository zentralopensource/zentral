from django.urls import path
from .api_views import StoreDetail, StoreList


app_name = "stores_api"
urlpatterns = [
    path('stores/', StoreList.as_view(), name="stores"),
    path('stores/<uuid:pk>/', StoreDetail.as_view(), name="store"),
]
