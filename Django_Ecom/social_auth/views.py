from rest_framework import generics, status
from rest_framework.response import Response
from .serializers import GoogleSocialAuthSerializer, GithubSocialAuthSerializer

# Create your views here.
class GoogleLoginView(generics.GenericAPIView):

    serializer_class = GoogleSocialAuthSerializer

    def post(self, request):

        serializer = self.serializer_class(data = request.data)
        serializer.is_valid(raise_exception = True)
        data = serializer.validated_data
        
        return Response(data, status = status.HTTP_200_OK)

class GithubLoginView(generics.GenericAPIView):

    serializer_class = GithubSocialAuthSerializer

    def post(self, request):

        serializer = self.serializer_class(data = request.data)
        serializer.is_valid(raise_exception = True)
        data = serializer.validated_data

        return Response(data, status = status.HTTP_200_OK)