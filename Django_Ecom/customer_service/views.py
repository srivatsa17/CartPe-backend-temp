from django.shortcuts import render
from rest_framework import generics, status, views
from rest_framework.permissions import AllowAny, IsAuthenticated
# from customer_service.serializers import ( UpdateCustomerInfoSerializer )
from rest_framework.response import Response
from customer_service.models import Customer
from auth_service.views import get_user_from_token
import re

# Create your views here.
def isUserInfoValid(first_name, last_name, gender, phone):

    if first_name:
        if len(first_name) < 3 or len(first_name) > 255 or not first_name.isalnum():
            return False

        return True

    if last_name:
        if len(last_name) < 1 or len(last_name) > 255 or not last_name.isalnum():
            return False

        return True

    if gender:
        if gender == 'Male' or gender == 'Female' or gender == 'Other':
            return True

        return False

    if phone:
        pattern = re.compile("(0|91)?[5-9][0-9]{9}")
        if not pattern.match(phone):
            return False
        return True

class UpdateCustomerInfo(generics.UpdateAPIView):

    permission_classes = [IsAuthenticated]

    def patch(self, request):

        token = request.headers.get('Authorization')
        user = get_user_from_token(token)

        data = request.data

        try:
            customer = Customer.objects.get(email = user)

            if 'first_name' in data.keys():
                if isUserInfoValid(data['first_name'], None, None, None):
                    user.first_name = data['first_name']
                    user.save(update_fields=['first_name'])

                    customer.first_name = data['first_name']
                    customer.save(update_fields=['first_name'])

                else:
                    response = {
                        "message": "Invalid first_name"
                    }
                    return Response(response, status=status.HTTP_400_BAD_REQUEST)

            if 'last_name' in data.keys():
                if isUserInfoValid(None, data['last_name'], None, None):
                    user.last_name = data['last_name']
                    user.save(update_fields=['last_name'])

                    customer.last_name = data['last_name']
                    customer.save(update_fields=['last_name'])

                else:
                    response = {
                        "message": "Invalid last_name"
                    }
                    return Response(response, status=status.HTTP_400_BAD_REQUEST)

            if 'gender' in data.keys():
                if isUserInfoValid(None, None, data['gender'], None):
                    customer.gender = data['gender']
                    customer.save(update_fields=['gender'])

                else:
                    response = {
                        "message": "Invalid gender"
                    }
                    return Response(response, status=status.HTTP_400_BAD_REQUEST)

            if 'phone' in data.keys():
                if isUserInfoValid(None, None, None, data['phone']):
                    customer.phone = data['phone']
                    customer.save(update_fields=['phone'])

                else:
                    response = {
                        "message": "Invalid phone number"
                    }
                    return Response(response, status=status.HTTP_400_BAD_REQUEST)

            response = {
                "data": data,
                "message": "User info updated successfully"
            }
            return Response(response, status = status.HTTP_200_OK)

        except Exception:
            response = {
                "message": "Unable to update user info"
            }

            return Response(response, status=status.HTTP_400_BAD_REQUEST)
