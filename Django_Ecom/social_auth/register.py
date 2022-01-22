from django.contrib import auth
from auth_service.models import User
import os
import random
from rest_framework.exceptions import AuthenticationFailed
from customer_service.models import Customer

def generate_username(name):

    username = "".join(name.split(' ')).lower()
    if not User.objects.filter(username = username).exists():
        return username
    else:
        random_username = username + str(random.randint(0, 1000))
        return generate_username(random_username)


def register_social_user(provider, email, name):
    filtered_user_by_email = User.objects.filter(email = email)

    if filtered_user_by_email.exists():

        if provider == filtered_user_by_email[0].auth_provider:

            try:
                registered_user = auth.authenticate(
                email = email, password = os.environ.get('SOCIAL_SECRET'))

                return {
                    'username': registered_user.username,
                    'email': registered_user.email,
                    'tokens': registered_user.tokens()
                }

            except:
                raise AuthenticationFailed(detail = 'Invalid credentials')

        else:
            raise AuthenticationFailed(
                detail = 'Please continue your login using ' + filtered_user_by_email[0].auth_provider)

    else:
        user = {
            'username': generate_username(name), 
            'email': email,
            'password': os.environ.get('SOCIAL_SECRET')
        }

        user = User.objects.create_user(**user)
        user.first_name = name.split(' ')[0] if len(name.split(' ')[0]) else ' '
        user.last_name = name.split(' ')[1] if len(name.split(' ')[1]) else ' '
        user.is_verified = True
        user.auth_provider = provider
        user.save()

        customer = Customer()
        customer.user = user
        customer.first_name = user.first_name
        customer.last_name = user.last_name
        customer.email = user.email
        customer.save()

        new_user = auth.authenticate(
            email = email, password = os.environ.get('SOCIAL_SECRET'))

        return {
            'email': new_user.email,
            'username': new_user.username,
            'tokens': new_user.tokens()
        }