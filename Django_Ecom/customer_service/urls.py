from django.urls import path
from .views import UpdateCustomerInfo

app_name = 'customer_service'

urlpatterns = [
    path('updateCustomerInfo/', UpdateCustomerInfo.as_view(), name = 'updateCustomerInfo'),
]