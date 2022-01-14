from django.db import models

# Create your models here.
from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin
)
from django.db import models
from rest_framework_simplejwt.tokens import RefreshToken

class UserManager(BaseUserManager):

    def create_user(self, username, email, password = None, first_name = None, last_name = None):

        if username is None:
            raise TypeError('Username should not be empty')

        if email is None:
            raise TypeError('Email should not be empty')
        
        user = self.model(
            username = username, 
            email = self.normalize_email(email),
            first_name = first_name,
            last_name = last_name
            )
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, username, email, password = None, first_name = None, last_name = None):

        if password is None:
            raise TypeError('Password should not be empty')

        user = self.create_user(username, email, password, first_name, last_name)
        user.is_superuser = True
        user.is_staff = True
        user.save()
        return user

AUTH_PROVIDERS = {
    'facebook': 'facebook',
    'google': 'google',
    'twitter': 'twitter',
    'email': 'email'
}

class User(AbstractBaseUser, PermissionsMixin):

    username = models.CharField(max_length = 255, unique = True, db_index = True)
    email = models.EmailField(max_length = 255, unique = True, db_index = True)
    first_name = models.CharField(max_length = 255, null = True, blank = True)
    last_name = models.CharField(max_length = 255, null = True, blank = True)
    is_verified = models.BooleanField(default = False)
    is_active = models.BooleanField(default = True)
    is_staff = models.BooleanField(default = False)
    password_reset_requested = models.BooleanField(default = False)
    created_at = models.DateTimeField(auto_now_add = True)
    updated_at = models.DateTimeField(auto_now = True)
    auth_provider = models.CharField(max_length = 255, blank = False, null = False,
                                    default = AUTH_PROVIDERS.get('email'))

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    objects = UserManager()

    def __str__(self):
        return self.email

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh_token': str(refresh),
            'access_token': str(refresh.access_token)
        }

