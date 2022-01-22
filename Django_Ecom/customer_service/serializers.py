from dataclasses import field
import os
import requests
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from customer_service.models import Customer
