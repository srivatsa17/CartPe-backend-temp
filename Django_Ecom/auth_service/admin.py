from django.contrib import admin
from auth_service.models import User
# Register your models here.

class UserAdmin(admin.ModelAdmin):
    list_display = [
        'first_name',
        'last_name',
        'username',
        'email',
        'is_active',
        'is_verified',
        'is_staff',
        'created_at',
        'updated_at',
        'auth_provider',
        'password_reset_requested'
    ]

admin.site.register(User, UserAdmin)