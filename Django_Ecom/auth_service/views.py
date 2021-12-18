import os
from django.shortcuts import render
from rest_framework import generics, status, views
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.serializers import Serializer
from .serializers import RegisterSerializer, LoginSerializer, EmailVerificationSerializer, ChangePasswordSerializer
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
import json
from django.http import HttpResponse, JsonResponse
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.core.mail import EmailMultiAlternatives
from django.contrib.auth.decorators import login_required

# Create your views here.
def has_numbers(inputString):
    return any(char.isdigit() for char in inputString)

def has_alphabets(inputString):
    return any(char.isalpha() for char in inputString)

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

        # current_site = get_current_site(request).domain
        # # relativeLink = reverse('email-verify')
        # relativeLink = ''
        # token = str(token)
        # absurl = "http://localhost:3000/auth/email-verify/"+token
        # email_body = 'Hi ' + user.username + ',\nUse link below to verify your email \n' + absurl

        # data = {
        #     'email_body': email_body,
        #     'email_subject': 'Verify your email',
        #     'email_to': user.email
        # }

        FRONTEND_URL = 'http://127.0.0.1:8000'
        BACKEND_URL = 'http://127.0.0.1:8000'
        verify_link = FRONTEND_URL + '/auth/email-verify/?token=' + str(token)
        subject, from_email, to = 'Verify Your Email', 'vatsaecommerce@gmail.com', user.email
        html_content = render_to_string('auth_service/verify_email.html', {'verify_link':verify_link, 'base_url': FRONTEND_URL, 'backend_url': BACKEND_URL}) 
        text_content = strip_tags(html_content) 

        msg = EmailMultiAlternatives(subject, text_content, from_email, [to])
        msg.attach_alternative(html_content, "text/html")
        msg.send()

        response = {
            'user_data': user_data,
            'token': str(token),
            'status code': status.HTTP_201_CREATED,
            'message': 'Registered successfully'
        }
        return Response(response) 

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
        # data = json.loads(request.body.decode('utf-8'))
        # print(data)
        # token = data['token']
        token = request.GET.get('token', '')

        if not token:
            return Response(
                {
                    'status': 'failure',
                    'message': 'No token information obtained',
                    'status code': status.HTTP_204_NO_CONTENT,
                },
            )

        # print("Token = " + token)
        try:
            payload = jwt.decode(token, os.environ.get('SECRET_KEY'), algorithms=["HS256"])
            # print(payload)
            user = User.objects.get(id = payload['user_id'])

            if not user.is_verified:
                user.is_verified = True
                user.save()

            response = {
                'status': 'success',
                'message': 'Email Successfully activated',
                'status code': status.HTTP_200_OK
            }

            return Response(response) 

        except jwt.ExpiredSignatureError:
            response = {
                'status': 'failure',
                'message': 'Activation link expired',
                'status code': status.HTTP_400_BAD_REQUEST
            }

            return Response(response)

        except jwt.exceptions.DecodeError:
            response = {
                'status': 'failure',
                'message':'Invalid token',
                'status code': status.HTTP_400_BAD_REQUEST
            }

            return Response(response)

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

            response = {
                'status': 'success',
                'message':'logged out successfully and token blacklisted',
                'status code': status.HTTP_200_OK
            }
            return Response(response)
            
        except Exception:
            response = {
                'status': 'failure',
                'message':'logout not successful',
                'status code': status.HTTP_400_BAD_REQUEST
            }

            return Response(response)

class ChangePasswordView(generics.UpdateAPIView):

    permission_classes = [IsAuthenticated]
    serializer_class = ChangePasswordSerializer

    def get_object(self, queryset=None):
        try:
            obj = self.request.user
            return obj

        except Exception:
            response = {
                'status': 'failure',
                "message": "Not logged in",
                "status code": status.HTTP_401_UNAUTHORIZED
            }

            return Response(response)

    def patch(self, request):
        self.object = self.get_object()
        serializer = self.serializer_class(data = request.data)
        serializer.is_valid(raise_exception = True)

        if serializer.is_valid():
            # Check old password
            old_password = serializer.data.get("old_password")
            new_password = serializer.data.get("new_password")

            if not self.object.check_password(old_password):
                response = {
                    'status': 'failure',
                    "message": "Wrong password.",
                    "status code": status.HTTP_400_BAD_REQUEST
                }

                return Response(response)

            if old_password == new_password:
                response = {
                    'status': 'failure',
                    "message":"New password is same as old password",
                    "status code": status.HTTP_400_BAD_REQUEST
                }

                return Response(response)

            if len(new_password) < 8:
                response = {
                    'status': 'failure',
                    "message":"Password length should be greater than 8 characters",
                    "status code": status.HTTP_400_BAD_REQUEST
                }

                return Response(response)

            if not has_alphabets(new_password):
                response = {
                    'status': 'failure',
                    "message":"Password should contain alphabets",
                    "status code": status.HTTP_400_BAD_REQUEST
                }

                return Response(response)

            if not has_numbers(new_password):
                response = {
                    'status': 'failure',
                    "message":"Password should contain digits",
                    "status code": status.HTTP_400_BAD_REQUEST
                }

                return Response(response)

            # set_password also hashes the password that the user will get
            self.object.set_password(new_password)
            self.object.save()

            response = {
                'status': 'success',
                'status code': status.HTTP_200_OK,
                'message': 'Password updated successfully',
            }

            return Response(response)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
