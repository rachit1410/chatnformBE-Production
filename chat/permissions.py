from rest_framework.permissions import BasePermission


class IsMember(BasePermission):
    def has_object_permission(self, request, view, obj):
        user = request.user
        return user in obj.group.group_members.all()
