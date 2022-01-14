import os
import requests
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from .register import register_social_user
from requests import ConnectionError

class GoogleSocialAuthSerializer(serializers.Serializer):
    token = serializers.CharField()
    
    def validate(self, token):
        tokenValue = token['token']

        try:
            requestURL = 'https://oauth2.googleapis.com/tokeninfo'
            requestParams = {'id_token': tokenValue}
            requestHeaders = {'content-type': 'application/json'}
            request = requests.get(requestURL, params=requestParams, headers=requestHeaders)
            user_data = request.json()
            user_data['sub']
        
        except ConnectionError:
            return "Could not connect to google api endpoint"

        except:
            raise serializers.ValidationError(
                'The token is invalid or expired. Please login again.'
            )

        if 'accounts.google.com' not in user_data['iss']:
            raise AuthenticationFailed('Invalid token')

        if user_data['aud'] != os.environ.get('GOOGLE_CLIENT_ID'):
            raise AuthenticationFailed('Invalid Client ID obtained')

        email = user_data['email']
        name = user_data['name']
        provider = 'google'

        return register_social_user(provider = provider, email = email, name = name) 