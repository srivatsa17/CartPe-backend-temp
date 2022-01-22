from django.db import models
from auth_service.models import User

# Create your models here.
GENDER_CHOICES = (
    ('Male', 'Male'),
    ('Female', 'Female'),
    ('Other', 'Other')
)

class Customer(models.Model):

    user = models.OneToOneField(User, on_delete = models.CASCADE, null = True, blank = True)
    email = models.EmailField(max_length = 255, unique = True, db_index = True)
    first_name = models.CharField(max_length = 255, null = True, blank = True)
    last_name = models.CharField(max_length = 255, null = True, blank = True)
    gender = models.CharField(max_length = 30, null = True, blank = True, choices = GENDER_CHOICES) 
    phone = models.CharField(max_length = 20, null = True, blank = True)
    profile_pic = models.ImageField(default = "guest-user-pic.jpg", null = True, blank = True)  

    def __str__(self):
        return str(self.email)

    @property
    def get_profile_picture(self):
        if self.profile_pic:
            return self.profile_pic.url
        else:
            return ''