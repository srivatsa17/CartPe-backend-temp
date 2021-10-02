from django.urls import path
from django.views.generic import TemplateView
from .views import RegisterView, VerifyEmail, LoginAPIView

app_name = 'auth_service'

urlpatterns = [
    path('register/', RegisterView.as_view(), name = 'register'),
    path('email-verify/', VerifyEmail.as_view(), name = 'email-verify'),
    path('login/', LoginAPIView.as_view(), name = 'login'),
    path('', TemplateView.as_view(template_name = 'auth_service/index.html'))
]