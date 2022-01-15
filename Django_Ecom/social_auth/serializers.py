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
            raise serializers.ValidationError("Could not connect to google api endpoint")

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

def getEmailFromGithubApi(githubAccessToken):
    requestURL = 'https://api.github.com/user/emails'
    requestHeaders = {'Authorization': 'Bearer ' + githubAccessToken}
    request = requests.get(requestURL, headers = requestHeaders)

    if request.status_code == 200:
        response = request.json()

        for jsonObject in response:
            if jsonObject['primary'] == True:
                email = jsonObject['email']
                break

    else:
        raise serializers.ValidationError(
            'The token is invalid or expired. Please login again.'
        )

    return email

def getNameFromGithubApi(githubAccessToken):
    requestURL = 'https://api.github.com/user'
    requestHeaders = {'Authorization': 'Bearer ' + githubAccessToken}
    request = requests.get(requestURL, headers = requestHeaders)

    if request.status_code == 200:
        response = request.json()

    else:
        raise serializers.ValidationError(
            'The token is invalid or expired. Please login again.'
        )

    return response['name']

class GithubSocialAuthSerializer(serializers.Serializer):
    token = serializers.CharField()

    def validate(self, token):
        tokenValue = token['token']

        try:
            requestURL = 'https://github.com/login/oauth/access_token'
            requestParams = {
                'client_id': os.environ.get('GITHUB_CLIENT_ID'),
                'redirect_uri': os.environ.get('GITHUB_REDIRECT_URI'),
                'client_secret': os.environ.get('GITHUB_CLIENT_SECRET'),
                'code': tokenValue
            }
            requestHeaders = {'content-type': 'application/json'}
            request = requests.post(requestURL, params=requestParams, headers=requestHeaders)
            githubAccessToken = request.text.split('&')[0].split('=')[1]

            email = getEmailFromGithubApi(githubAccessToken)
            name = getNameFromGithubApi(githubAccessToken)
            provider = 'github'

        except ConnectionError:
            raise serializers.ValidationError("Could not connect to github api endpoint")

        except:
            raise serializers.ValidationError(
                'The token is invalid or expired. Please login again...'
            )

        return register_social_user(provider = provider, email = email, name = name) 