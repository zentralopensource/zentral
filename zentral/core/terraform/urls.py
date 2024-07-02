from django.urls import path
from . import views

app_name = "terraform"
urlpatterns = [
    path('', views.IndexView.as_view(), name='index'),
    path('states/<int:pk>/', views.StateView.as_view(), name='state'),
]
