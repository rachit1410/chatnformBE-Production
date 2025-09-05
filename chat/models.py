from django.db import models
from django.contrib.auth import get_user_model
from chat.choices import GROUP_TYPES, MESSAGE_TYPE, ROLE_CHOICES
import uuid
from django.utils import timezone


class Base(models.Model):
    uid = models.UUIDField(default=uuid.uuid4, primary_key=True, unique=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class Image(Base):
    image = models.ImageField(upload_to='images')


class ChatGroup(Base):
    User = get_user_model()
    group_owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name="my_groups")
    group_name = models.CharField(max_length=255, unique=True)
    group_description = models.TextField(null=True, blank=True)
    group_profile = models.ForeignKey(Image, related_name="group_image", on_delete=models.SET_NULL, null=True, blank=True)
    group_type = models.CharField(max_length=100, choices=GROUP_TYPES, default='private')

    def __str__(self):
        return self.group_name


class JoinRequest(Base):
    User = get_user_model()
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name="sent_requests")
    group = models.ForeignKey(ChatGroup, on_delete=models.CASCADE, related_name="join_requests")
    
    class Meta:
        unique_together = ('sender', 'group')


class Member(Base):
    User = get_user_model()
    group = models.ForeignKey(ChatGroup, on_delete=models.CASCADE, related_name="group_members")
    member = models.ForeignKey(User, related_name="joined_groups", on_delete=models.CASCADE)
    role = models.CharField(max_length=100, default="regular", choices=ROLE_CHOICES)

    def __str__(self):
        return f"{self.member.name} - {self.group.group_name} ({self.role})"



class File(Base):
    User = get_user_model()
    file = models.FileField(upload_to="files/")
    uploaded_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name="uploaded_files")

    def __str__(self):
        return self.file.name
    
    @property
    def is_expired(self, lifetime_hours=24):
        return timezone.now() > self.created_at + timezone.timedelta(hours=lifetime_hours)


class GroupChat(Base):
    User = get_user_model()
    group = models.ForeignKey(ChatGroup, on_delete=models.CASCADE, related_name="group_chats")
    sent_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name="messages", null=True, blank=True)
    message_type = models.CharField(max_length=100, choices=MESSAGE_TYPE)
    text_message = models.TextField(null=True, blank=True)
    file_message = models.URLField(max_length=200, null=True, blank=True)
    deleted_for = models.ManyToManyField(User, related_name="deleted_messages")

    @property
    def filename(self):
        if self.message_type == 'file' and self.file_message:
            return f"download/{self.file_message.split('/')[-1]}"
        return None

    def __str__(self):
        if self.message_type == 'text':
            return f"Message by {self.sent_by.name} in {self.group.group_name}: {self.uid}"
        elif self.message_type == 'file':
            return f"File message by {self.sent_by.name} in {self.group.group_name}: {self.filename}"
