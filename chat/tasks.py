from chat.models import Member, Image, ChatGroup
from django.contrib.auth import get_user_model
import json
import logging
from celery import shared_task
logger = logging.getLogger(__name__)


@shared_task
def finalize_group_creation(group_uid, member_ids=None, image_uid=None):
    """
    Runs in worker process; accepts only serializable arguments.
    - group_uid: str
    - member_ids: list of ints (or empty list)
    - image_uid: str or None
    """
    User = get_user_model()
    try:
        group = ChatGroup.objects.get(uid=group_uid)
    except ChatGroup.DoesNotExist:
        logger.error(f"finalize_group_creation: group {group_uid} not found")
        return

    # create owner as admin if not exists
    try:
        owner = group.group_owner
        Member.objects.get_or_create(member=owner, group=group, defaults={"role": "admin"})
    except Exception as e:
        logger.exception(f"Error ensuring owner member for group {group_uid}: {e}")

    # attach image if provided
    if image_uid:
        try:
            image = Image.objects.get(uid=image_uid)
            group.group_profile = image
            group.save()
        except Image.DoesNotExist:
            logger.error(f"finalize_group_creation: image {image_uid} not found")
        except Exception as e:
            logger.exception(f"finalize_group_creation: failed to attach image {image_uid} -> {e}")

    # create other members (member_ids expected as list)
    if member_ids:
        try:
            if isinstance(member_ids, str):
                member_ids = json.loads(member_ids)
            if not isinstance(member_ids, list):
                member_ids = [member_ids]
        except Exception:
            logger.exception("finalize_group_creation: failed to parse member_ids")

        members_to_create = []
        for mid in member_ids:
            try:
                user = User.objects.get(id=mid)
                # avoid duplicating owner/admin
                if user == group.group_owner:
                    continue
                members_to_create.append(Member(member=user, group=group, role="regular"))
            except User.DoesNotExist:
                logger.warning(f"finalize_group_creation: user {mid} not found, skipping")

        if members_to_create:
            try:
                Member.objects.bulk_create(members_to_create)
            except Exception as e:
                logger.exception(f"finalize_group_creation: bulk_create failed: {e}")
