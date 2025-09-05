from django.db import models
from django.contrib.auth.models import AbstractUser
from accounts.manager import CNFManager


class CNFUser(AbstractUser):
    username = None
    name = models.CharField(max_length=255)
    email = models.EmailField(max_length=254, verbose_name="email address", unique=True)
    profile_image = models.ImageField(upload_to="profile", null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["name"]
    objects = CNFManager()

    def __str__(self):
        return self.email

    class Meta:
        verbose_name = "CNFUser"


class VerifiedEmail(models.Model):
    email = models.EmailField(max_length=254, verbose_name="email address", unique=True)
    verified = models.BooleanField(default=False)
