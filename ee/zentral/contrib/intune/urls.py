from django.urls import path
from . import views

app_name = "intune"
urlpatterns = [
    # index
    path('', views.IndexView.as_view(), name="index"),

    # Tenants
    path('tenants/', views.TenantListView.as_view(), name="tenants"),
    path('tenants/create/', views.CreateTenantView.as_view(), name="create_tenant"),
    path('tenants/<int:pk>/', views.TenantView.as_view(), name="tenant"),
    path('tenants/<int:pk>/update/', views.UpdateTenantView.as_view(), name="update_tenant"),
    path('tenants/<int:pk>/delete/', views.DeleteTenantView.as_view(), name="delete_tenant"),
]


setup_menu_cfg = {
    'items': (
        ('index', 'Overview', False, ('intune.index',)),
        ('tenants', 'Tenants', False, ('intune.view_tenant',)),
    )
}
