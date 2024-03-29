import os
from django.shortcuts import render
from rest_framework import generics, status, views
from rest_framework.permissions import AllowAny
from rest_framework.serializers import Serializer
from .serializers import RegisterSerializer, EmailVerificationSerializer, LoginSerializer
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User
from .utils import Util
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
import jwt
from django.conf import settings
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

# Create your views here.

class RegisterView(generics.GenericAPIView):

    serializer_class = RegisterSerializer

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data = user)
        serializer.is_valid(raise_exception = True)
        serializer.save()

        user_data = serializer.data

        user = User.objects.get(email = user_data['email'])

        token = RefreshToken.for_user(user).access_token

        current_site = get_current_site(request).domain
        # relativeLink = reverse('email-verify')
        relativeLink = ''
        absurl = 'http://'+current_site+"/"+"auth/email-verify/?token="+str(token)
        email_body = 'Hi ' + user.username + ',\nUse link below to verify your email \n' + absurl

        data = {
            'email_body': email_body,
            'email_subject': 'Verify your email',
            'email_to': user.email
        }

        Util.send_email(data)

        return Response(
            user_data, 
            status = status.HTTP_201_CREATED
        ) 

class VerifyEmail(views.APIView):
    
    serializer_class = EmailVerificationSerializer

    token_param_config = openapi.Parameter(
                            'token', 
                            in_=openapi.IN_QUERY,
                            description = 'Add token to verify your email-id',
                            type = openapi.TYPE_STRING
                        )

    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token, os.environ.get('SECRET_KEY'), algorithms=["HS256"])
            print(payload)
            user = User.objects.get(id = payload['user_id'])

            if not user.is_verified:
                user.is_verified = True
                user.save()

            return Response(
                {
                    'email': 'Successfully activated'
                }, 
                status = status.HTTP_200_OK
            ) 

        except jwt.ExpiredSignatureError:
            return Response(
                {
                    'error': 'Activation link expired'
                },
                status = status.HTTP_400_BAD_REQUEST
            )

        except jwt.exceptions.DecodeError:
            return Response(
                {
                    'error':'Invalid token'
                },
                status = status.HTTP_400_BAD_REQUEST
            )

class LoginAPIView(generics.GenericAPIView):

    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data = request.data)
        serializer.is_valid(raise_exception = True)

        return Response(
            serializer.data,
            status = status.HTTP_200_OK
        )

class LogoutAPIView(views.APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(
                {
                    'message':'logged out successfully and token blacklisted'
                },
                status = status.HTTP_200_OK
            )
        except Exception:
            return Response(
                {
                    'message':'logout not successful'
                },
                status = status.HTTP_400_BAD_REQUEST
            )