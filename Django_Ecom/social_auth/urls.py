from django.urls import path
from .views import GoogleLoginView, GithubLoginView

app_name = 'social_auth'

urlpatterns = [
    path('google/', GoogleLoginView.as_view(), name = 'google'),
    path('github/', GithubLoginView.as_view(), name = 'github')
]