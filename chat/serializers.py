from rest_framework import serializers
from chat.models import ChatGroup, Member, JoinRequest, GroupChat, Image
from accounts.serializers import CNFUserSerializer
from cryptography.fernet import Fernet
from django.conf import settings

fernet = Fernet(settings.FERNET_KEY)

class ImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Image
        fields = ['image']


class GroupSerialiazer(serializers.ModelSerializer):
    group_profile = ImageSerializer(required=False)

    class Meta:
        model = ChatGroup
        exclude = ['updated_at']

    def validate(self, data):
        if data.get('group_name') and not isinstance(data.get('group_name'), str):
            raise serializers.ValidationError("group_name must be a string.")
        if data.get('group_name') and ChatGroup.objects.filter(group_name=data.get('group_name')):
            raise serializers.ValidationError("group name already exists.")
        if not data.get('group_type') or data.get('group_type') not in ['private', 'public']:
            data['group_type'] = 'private'
        return data


class MemberSerializer(serializers.ModelSerializer):
    member = CNFUserSerializer()
    group = GroupSerialiazer()

    class Meta:
        model = Member
        exclude = ['created_at', 'updated_at']


class RequestSerializer(serializers.ModelSerializer):
    group = GroupSerialiazer()
    sender = CNFUserSerializer()

    class Meta:
        model = JoinRequest
        exclude = ['updated_at']


class ChatSerializer(serializers.ModelSerializer):
    sent_by = CNFUserSerializer()
    group = ChatGroup()
    text_message = serializers.SerializerMethodField()

    class Meta:
        model = GroupChat
        fields = ['sent_by', 'group', 'message_type', 'text_message', 'file_message', 'created_at', 'uid']

    def get_text_message(self, obj):
        """Decrypt text_message before sending to frontend."""
        if obj.text_message:
            try:
                return fernet.decrypt(obj.text_message.encode()).decode()
            except Exception:
                # In case message is corrupted or was saved without encryption
                return obj.text_message
        return None

    def delete(self, request):
        message = self.queryset

        if message.sent_by.id == request.user.id:
            message.delete()
        else:
            message.deleted_for.add(request.user.id)
