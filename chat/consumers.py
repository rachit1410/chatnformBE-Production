import json
import uuid
import logging
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.exceptions import StopConsumer
from asgiref.sync import sync_to_async
from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.core.cache import cache
from cryptography.fernet import Fernet
from chat.kafka_utils import send_realtime_event
from chat.utils import is_member

logger = logging.getLogger(__name__)
fernet = Fernet(settings.FERNET_KEY)


class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        try:
            user = self.scope.get("user")
            self.group_name = self.scope.get("group_id")

            # Check if user and group_id were successfully set by the middleware
            if not user or not self.group_name:
                logger.info("Connection attempt without a valid user or group ID.")
                await self.close(code=4001)  # Use a custom close code
                return

            if user and await is_member(self.group_name, user):
                await self.channel_layer.group_add(
                    self.group_name,
                    self.channel_name
                )

                # accept first, then attempt send; protect send with try/except
                await self.accept()
                try:
                    await self.send(text_data=json.dumps({"message": "connection made."}))
                except Exception as send_exc:
                    # client disconnected before/while we tried to send; log and stop
                    logger.info(f"Client disconnected during initial send: {send_exc}")
                    return
            else:
                logger.info("Not authorized.")
                # try close but ignore errors if socket already closed
                try:
                    await self.close()
                except Exception:
                    logger.debug("Socket already closed while attempting to close on unauthorized connect.")
        except Exception as e:
            logger.exception(f"Error during WebSocket connect:{e}")
            # closing may fail if client already disconnected; ignore secondary errors
            try:
                await self.close(code=1011)
            except Exception:
                logger.debug("Ignored error while closing after connect exception.")
    
    async def receive(self, text_data=None):
        from chat.models import ChatGroup, GroupChat
        User = get_user_model()

        try:
            data = json.loads(text_data)
            sender_id = data.get("sender")
            msg_id = data.get("id") or str(uuid.uuid4())
            group_id = self.group_name

            # Deduplication check (client retries, etc.)
            cache_key = f"chat_msg_{msg_id}"
            if cache.get(cache_key):
                logger.info(f"Duplicate message {msg_id} ignored for group {group_id}")
                return
            cache.set(cache_key, True, timeout=60)

            # Verify membership
            group = await sync_to_async(ChatGroup.objects.get)(
                uid=uuid.UUID(group_id),
                group_members__member__id=sender_id
            )
            sent_by = await sync_to_async(User.objects.get)(id=sender_id)

            raw_message = data.get("message", "") or ""
            encrypted_message = (
                fernet.encrypt(raw_message.encode("utf-8")).decode("utf-8")
                if raw_message else ""
            )

            message_data = {
                "id": msg_id,
                "sender_id": sender_id,
                "sender_name": getattr(sent_by, "name", getattr(sent_by, "username", "")),
                "group_id": group_id,
                "message": encrypted_message,
                "file": data.get("file_url"),
                "message_type": data.get("message_type", "text"),
                "timestamp": timezone.now().isoformat(),
            }

            # Save to DB
            await sync_to_async(GroupChat.objects.create)(
                group=group,
                sent_by=sent_by,
                message_type=message_data["message_type"],
                text_message=encrypted_message,
                file_message=message_data["file"]
            )

            # Publish only to Kafka (no direct echo here)
            await sync_to_async(send_realtime_event)(
                settings.KAFKA_TOPIC,
                message_data,
                origin=self.channel_name  # tag sender channel
            )

        except ChatGroup.DoesNotExist:
            try: 
                await self.send(text_data=json.dumps(
                    {"error": "You are not authorised to message in this group."}
                ))
            except Exception as send_exc:
                    # client disconnected before/while we tried to send; log and stop
                    logger.info(f"Client disconnected during initial send: {send_exc}")
                    return
        except StopConsumer:
            try: 
                await self.close()
            except Exception:
                    logger.debug("Socket already closed while attempting to close on unauthorized connect.")
        except Exception as e:
            logger.exception(f"Error during message receive: {e}")
            try:
                await self.send(text_data=json.dumps({"error": "Message processing error."}))
            except Exception as send_exc:
                logger.info(f"Client disconnected during error send: {send_exc}")
                return

    async def disconnect(self, close_code):
        logger.info(f"WebSocket disconnected: {close_code}")
        user = self.scope["user"]
        if user and user.is_authenticated:
            cache_key = f"ws_active_{user.id}_{self.group_name}"
            # Only clear if this channel is the current one
            if cache.get(cache_key) == self.channel_name:
                cache.delete(cache_key)

        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def send_realtime_data(self, event):
        logger.info("sending message to WebSocket")
        data = event["data"]

        # Skip if this is the origin socket
        if data.get("origin") == self.channel_name:
            return

        try:
            decrypted_msg = None
            if data.get("message"):
                try:
                    decrypted_msg = fernet.decrypt(data["message"].encode("utf-8")).decode("utf-8")
                except Exception:
                    decrypted_msg = data["message"]
            
            try: 
                await self.send(text_data=json.dumps({
                    "id": data.get("id"),
                    "type": data.get("message_type", "text"),
                    "message": decrypted_msg,
                    "sender_id": data.get("sender_id"),
                    "sender_name": data.get("sender_name"),
                    "file": data.get("file"),
                    "timestamp": data.get("timestamp")
                }))
            except Exception as send_exc:
                    # client disconnected before/while we tried to send; log and stop
                    logger.info(f"Client disconnected during initial send: {send_exc}")
                    return
        except Exception as e:
            logger.error(f"Failed to send message: {e}")
            try:
                await self.close(code=1011)
            except Exception:
                    logger.debug("Socket already closed while attempting to close on unauthorized connect.")

    # 🔑 Handle duplicate connection cleanup
    async def force_disconnect(self, event):
        logger.info("Force disconnecting duplicate socket")
        try:
            await self.close()
        except Exception:
            logger.debug("Socket already closed while attempting to close on unauthorized connect.")
