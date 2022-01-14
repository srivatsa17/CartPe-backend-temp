from django.urls import path
from .views import GoogleLoginView 

app_name = 'social_auth'

urlpatterns = [
    path('google/', GoogleLoginView.as_view(), name = 'google')
]