from channels.db import database_sync_to_async
from chat.models import ChatGroup
from uuid import UUID


@database_sync_to_async
def is_member(group_id, user):
    return ChatGroup.objects.filter(uid=UUID(group_id), group_members__member__id=user.id).exists()
