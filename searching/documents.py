from django_elasticsearch_dsl import Document, fields
from django_elasticsearch_dsl.registries import registry
from django.contrib.auth import get_user_model
from chat.models import ChatGroup


@registry.register_document
class UserDocument(Document):
    class Index:
        # Name of the Elasticsearch index
        name = 'users'
        # See Elasticsearch Indices API reference for available settings
        settings = {'number_of_shards': 1,
                    'number_of_replicas': 0}

    class Django:
        User = get_user_model()
        model = User

        fields = [
            'id',
            'name',
            'profile_image'
        ]


@registry.register_document
class GroupDocument(Document):

    group_owner = fields.ObjectField(properties={
        "id": fields.IntegerField(),
        "name": fields.TextField(),
    })
    
    group_profile = fields.ObjectField(properties={
        "image": fields.TextField(attr="image.url"),
    })

    class Index:
        # Name of the Elasticsearch index
        name = 'groups'
        # See Elasticsearch Indices API reference for available settings
        settings = {'number_of_shards': 1,
                    'number_of_replicas': 0}
    class Django:
        model = ChatGroup

        fields = [
            'uid',
            'group_name',
            'group_type'
        ]

        def get_queryset(self):
            return super().get_queryset().filter(group_type="public").exclude(group_members__member__id=self.request.user.id).exclude(join_requests__sender=self.request.user)
