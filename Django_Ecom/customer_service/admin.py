from django.contrib import admin

from customer_service.models import Customer

# Register your models here.
class CustomerAdmin(admin.ModelAdmin):
    list_display = [
        'id',
        'user',
        'first_name',
        'last_name',
        'email',
        'gender',
        'phone',
        'profile_pic'
    ]

admin.site.register(Customer, CustomerAdmin)