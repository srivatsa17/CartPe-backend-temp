from django.db.models import fields
from rest_framework import serializers
from .models import User
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        max_length = 68,
        min_length = 6,
        write_only = True
    )

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'username', 'password']

    def validate(self, attrs):
        email = attrs.get('email', '')
        username = attrs.get('username', '')

        if not username.isalnum():
            raise serializers.ValidationError('The username should only contain alphanumeric characters')

        return attrs

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)

class LoginSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(max_length = 255, min_length = 2, read_only = True)
    last_name = serializers.CharField(max_length = 255, min_length = 1, read_only = True)
    email = serializers.EmailField(max_length = 255, min_length = 3)
    username = serializers.CharField(max_length = 255, min_length = 3, read_only = True)
    password = serializers.CharField(max_length = 68, min_length = 6, write_only = True)
    tokens = serializers.CharField(max_length = 150, min_length = 6, read_only = True)

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'password', 'username', 'tokens']

    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')

        user = auth.authenticate(email = email, password = password)

        if not user:
            raise AuthenticationFailed('Invalid credentials, try again')
        
        if not user.is_active:
            raise AuthenticationFailed('Account disabled')

        if not user.is_verified:
            raise AuthenticationFailed('Email is not verified')
        
        return {
            'email':user.email,
            'username':user.username,
            'tokens':user.tokens
        }
        
class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length = 555)

    class Meta:
        model = User
        fields = ['token']

class ChangePasswordSerializer(serializers.ModelSerializer):
    old_password = serializers.CharField(min_length = 6, max_length = 255, required = True)
    new_password = serializers.CharField(min_length = 6, max_length = 255, required = True)
    confirm_password = serializers.CharField(min_length = 6, max_length = 255, required = True)

    class Meta:
        model = User
        fields = ['old_password', 'new_password', 'confirm_password']
