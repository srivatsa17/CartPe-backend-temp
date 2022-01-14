from django.shortcuts import render
from rest_framework import generics, status, views
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from .serializers import GoogleSocialAuthSerializer
import requests, json
from types import SimpleNamespace

# Create your views here.
class GoogleLoginView(generics.GenericAPIView):

    serializer_class = GoogleSocialAuthSerializer

    def post(self, request):

        serializer = self.serializer_class(data = request.data)
        serializer.is_valid(raise_exception = True)
        data = serializer.validated_data
        
        return Response(data, status = status.HTTP_200_OK)
        

        
