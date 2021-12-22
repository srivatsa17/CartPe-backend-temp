import os
from django.shortcuts import render
from rest_framework import generics, status, views
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.serializers import Serializer
from .serializers import RegisterSerializer, LoginSerializer, EmailVerificationSerializer, ChangePasswordSerializer
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User
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
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_text
from .tokens import account_activation_token

# Create your views here.
#############################################################
#
#   Function for validating digits
#
#############################################################

def has_numbers(inputString):
    return any(char.isdigit() for char in inputString)

#############################################################
#
#   Function for validating alphabets
#
#############################################################

def has_alphabets(inputString):
    return any(char.isalpha() for char in inputString)

#############################################################
#
#   Function for validating bearer token
#
#############################################################

def get_user_from_token(token):

    try:
        if token.split(' ')[0] == 'Bearer':
            token = token.split(' ')[1]
            
        else:
            response = {
                "message": "Invalid token"
            }

            return Response(response, status = status.HTTP_401_UNAUTHORIZED)

        payload = jwt.decode(token, os.environ.get('SECRET_KEY'), algorithms=["HS256"])
        # print(payload)
        user = User.objects.get(id = payload['user_id'])
        
        return user
    
    except Exception:
        response = {
            "message": "Invalid token"
        }

        return Response(response, status = status.HTTP_401_UNAUTHORIZED)

#############################################################
#
#   Function for validating passwords
#
#############################################################

def valid_password_checker(user, old_password, new_password, confirm_password):

    isValid = 1

    if not user.check_password(old_password):
        isValid = 0
        response = {
            "message": "Wrong password."
        }

    if old_password == new_password:
        isValid = 0
        response = {
            "message":"New password is same as old password"
        }

    if len(new_password) < 8:
        isValid = 0
        response = {
            "message":"Password length should be greater than 8 characters"
        }

    if not has_alphabets(new_password):
        isValid = 0
        response = {
            "message":"Password should contain alphabets"
        }

    if not has_numbers(new_password):
        isValid = 0
        response = {
            "message":"Password should contain digits"
        }

    if new_password != confirm_password:
        isValid = 0
        response = {
            "message":"Passwords does not match"
        }

    if isValid == 1:
        response = {
            "message":"New Password is valid"
        }
        return Response(response, status = status.HTTP_200_OK)

    return Response(response, status = status.HTTP_400_BAD_REQUEST)

#############################################################
#
#   Function for registering a user account
#
#############################################################

class RegisterView(generics.GenericAPIView):

    serializer_class = RegisterSerializer

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data = user)
        serializer.is_valid(raise_exception = True)
        serializer.save()

        user_data = serializer.data

        user = User.objects.get(email = user_data['email'])

        domain = get_current_site(request).domain
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = account_activation_token.make_token(user)

        subject, from_email, to = 'Verify Your Email', 'vatsaecommerce@gmail.com', user.email
        html_content = render_to_string(
                        'auth_service/verify_email.html', 
                        {
                            'domain':domain,
                            'uid':uid,
                            'token':token
                        }
                    )
        text_content = strip_tags(html_content) 

        msg = EmailMultiAlternatives(subject, text_content, from_email, [to])
        msg.attach_alternative(html_content, "text/html")
        msg.send()

        response = {
            'user_data': user_data,
            'message': 'Registered successfully'
        }
        return Response(response, status = status.HTTP_201_CREATED) 

#############################################################
#
#   Function for verifying a user account
#
#############################################################

class VerifyEmail(views.APIView):
    
    serializer_class = EmailVerificationSerializer

    token_param_config = openapi.Parameter(
                            'token', 
                            in_=openapi.IN_QUERY,
                            description = 'Add token to verify your email-id',
                            type = openapi.TYPE_STRING
                        )

    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self, request, uidb64, token):
        user = None
        try:
            uid = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk = uid)

        except Exception:
            user = None

        if user is not None and account_activation_token.check_token(user, token):
            user.is_verified = True
            user.save()

            response = {
                "message":"Email activated successfully"
            }
            return Response(response, template_name='', status = status.HTTP_200_OK)

        else:
            response = {
                "message":"Activation link is invalid"
            }
            return Response(response, template_name='', status = status.HTTP_400_BAD_REQUEST)

#############################################################
#
#   Function for logging in a user
#
#############################################################

class LoginAPIView(generics.GenericAPIView):

    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data = request.data)
        serializer.is_valid(raise_exception = True)

        return Response(
            serializer.data,
            status = status.HTTP_200_OK
        )

#############################################################
#
#   Function for logging out a user
#
#############################################################

class LogoutAPIView(views.APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)
            token.blacklist()

            response = {
                "message":"logged out successfully"
            }
            return Response(response, status = status.HTTP_200_OK)
            
        except Exception:
            response = {
                "message":"logout not successful"
            }

            return Response(response, status = status.HTTP_400_BAD_REQUEST)

#############################################################
#
#   Function for changing a user password
#
#############################################################

class ChangePasswordView(generics.UpdateAPIView):

    permission_classes = [IsAuthenticated]
    serializer_class = ChangePasswordSerializer

    def patch(self, request):
        token = request.headers.get('Authorization')
        user = get_user_from_token(token)
        
        serializer = self.serializer_class(data = request.data)
        serializer.is_valid(raise_exception = True)

        if serializer.is_valid():
            old_password = serializer.data.get("old_password")
            new_password = serializer.data.get("new_password")
            confirm_password = serializer.data.get("confirm_password")

            isNewPasswordValid = valid_password_checker(user, old_password, new_password, confirm_password)

            # set_password also hashes the password that the user will get
            if isNewPasswordValid.status_code == 200:
                
                user.set_password(new_password)
                user.save()

                response = {
                    'message': 'Password updated successfully'
                }
                return Response(response, status = status.HTTP_200_OK)

            else:
                return Response(isNewPasswordValid.data, status = isNewPasswordValid.status_code)

        return Response(serializer.errors, status = status.HTTP_400_BAD_REQUEST)
