from django.contrib import admin
from chat.models import (
    Image,
    ChatGroup,
    JoinRequest,
    Member,
    GroupChat,
)

admin.site.register(Image)
admin.site.register(ChatGroup)
admin.site.register(JoinRequest)
admin.site.register(Member)
admin.site.register(GroupChat)
