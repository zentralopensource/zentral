from django.urls import path
from . import views
from realms.backends.saml.urls import urlpatterns as saml_urlpatterns
from realms.backends.openidc.urls import urlpatterns as openidc_urlpatterns


app_name = "realms"
urlpatterns = [
    path('', views.RealmListView.as_view(), name='list'),
    path('<slug:backend>/create/', views.CreateRealmView.as_view(), name='create'),
    path('<uuid:pk>/', views.RealmView.as_view(), name='view'),
    path('<uuid:pk>/update/', views.UpdateRealmView.as_view(), name='update'),
    path('<uuid:pk>/zentral_login/', views.ZentralLoginView.as_view(), name='zentral_login'),
]
urlpatterns += saml_urlpatterns
urlpatterns += openidc_urlpatterns


setup_menu_cfg = {
    'items': (
        ('list', 'List'),
    )
}
