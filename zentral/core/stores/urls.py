from django.urls import path

from . import views

app_name = "stores"
urlpatterns = [
    path('', views.IndexView.as_view(), name='index'),
    path('<uuid:pk>/', views.StoreView.as_view(), name='store'),
]
