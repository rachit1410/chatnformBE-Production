from django.contrib import admin
from accounts.models import CNFUser, VerifiedEmail


@admin.register(CNFUser)
class CNFUserAdmin(admin.ModelAdmin):
    list_display = [
        "name",
        "email",
        "created_at",
        "updated_at",
    ]


@admin.register(VerifiedEmail)
class VerifiedEmailAdmin(admin.ModelAdmin):
    list_display = [
        "email",
        "verified"
    ]
