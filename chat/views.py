from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import generics
from chat.serializers import GroupSerialiazer, ChatSerializer, MemberSerializer, RequestSerializer
from chat.models import ChatGroup, Member, GroupChat, JoinRequest, File, Image
import logging
from rest_framework.permissions import IsAuthenticated
from chat.permissions import IsMember
from uuid import UUID
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework import status
from chat.tasks import finalize_group_creation
import json
from django.db import transaction
logger = logging.getLogger()


class CreateGroupAPI(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        # Fetch a single group if user is member. Simple DB lookup, keep inline.
        # Good: checking membership on query level.
        # Bad: returning 500 for "group not found". That's a 404, not server error.
        group_id = request.GET.get("group")
        if group_id:
            try:
                queryset = ChatGroup.objects.get(uid=UUID(group_id), group_members__member__id=request.user.id)
                serializer = GroupSerialiazer(queryset)
                return Response(
                    {
                        "status": True,
                        "message": "group fetched",
                        "data": serializer.data
                    }
                )
            except ChatGroup.DoesNotExist:
                logger.error(f"The chat user was looking for does not exists or he is not a member.")
                return Response(
                    {
                        "status": False,
                        "message": "the group you are trying to access does not exists or you are not a member.",
                        "data": {}
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            except Exception as e:
                logger.error(f"an unaxpected error occurred while getting group: {e}")
                return Response(
                    {
                        "status": False,
                        "message": "something went wrong.",
                        "data": {}
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
    def post(self, request):
        # Create new group.
        # After saving, you call finalize_group_creation(data, serializer).
        # If that function does heavy stuff (set up default channels, invite logic, 
        # indexing in Elasticsearch, uploading profile images), that belongs in Celery.
        # If it’s just creating DB rows, leave it inline.

        try:
            logger.info("post method called in CreateGroupAPI")
            data = request.data.copy()
            data["group_owner"] = request.user.pk
            
            # parse memberIds if sent as JSON string
            raw_member_ids = data.get("memberIds")
            member_ids = None
            if raw_member_ids:
                try:
                    if isinstance(raw_member_ids, str):
                        member_ids = json.loads(raw_member_ids)
                    else:
                        member_ids = raw_member_ids
                    # normalize
                    if not isinstance(member_ids, list):
                        member_ids = [member_ids]
                except Exception:
                    member_ids = None
            
                        # detach file from payload and save synchronously (avoid passing file handles to Celery)
            uploaded_image = None
            if request.FILES.get("group_profile"):
                uploaded_image = request.FILES.get("group_profile")    

            serializer = GroupSerialiazer(data=data)
            if serializer.is_valid():
                logger.info("serializer is valid")
                group = serializer.save()
                                # Save group synchronously inside a transaction
                with transaction.atomic():
                    group = serializer.save()

                    image_uid = None
                    if uploaded_image:
                        img = Image.objects.create(image=uploaded_image)
                        group.group_profile = img
                        group.save()
                        image_uid = str(img.uid)
                try:
                    payload_group_uid = str(group.uid)
                    if hasattr(finalize_group_creation, "delay"):
                        finalize_group_creation.delay(payload_group_uid, member_ids or [], image_uid)
                    else:
                        # fallback to direct call (local)
                        finalize_group_creation(payload_group_uid, member_ids or [], image_uid)
                except Exception as task_exc:
                    logger.exception(f"failed to enqueue finalize_group_creation: {task_exc}")
                return Response(
                    {
                        "status": True,
                        "message": "group created successfully.",
                        "data": serializer.data
                    }
                )
            logger.log("serializer is not valid")
            logger.error(f"serializer errors: {serializer.errors}")
            return Response(
                {
                    "status": False,
                    "message": serializer.errors,
                    "data": {}
                }
            )

        except Exception as e:
            logger.error(f"an unexpected error occurred while creating group: {e}")
            return Response(
                {
                    "status": False,
                    "message": "something went wrong.",
                    "data": {}
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def patch(self, request):
        # Update group details.
        # update_image(profile, group) is suspicious: if it's resizing/uploading files,
        # push it to Celery.
        # Serializer save is lightweight, fine inline.

        user = request.user
        group_id = UUID(request.data.get('uid'))
        try:
            group = ChatGroup.objects.get(
                uid=group_id,
                group_members__member=user,
                group_members__role="admin"
            )

            profile = request.data.get("group_profile")
            if profile:
                if group.group_profile is not None:
                    if Image.objects.filter(image=group.group_profile.image).exists():
                        group_profile = Image.objects.get(image=group.group_profile.image)
                        group_profile.image = profile
                        group_profile.save()
                        logger.info("image updated.")
                else:
                    group_profile = Image.objects.create(image=profile)
                    group.group_profile = group_profile
                    group.save()
                    logger.info("image created.")

            serializer = GroupSerialiazer(group, data=request.data, partial=True)

            if serializer.is_valid():
                serializer.save()
                return Response(
                    {
                        "status": True,
                        "message": "group updated successfully.",
                        "data": {}
                    }
                )
            return Response(
                {
                    "status": False,
                    "message": serializer.errors,
                    "data": {}
                }
            )
        except ChatGroup.DoesNotExist:
            return Response(
                {
                    "status": False,
                    "message": "group not found or you do not have permission to update this group.",
                    "data": {}
                }
            )

    def delete(self, request):
        # Deletes a group owned by current user. Simple DB op, no Celery needed.
        user = request.user
        group_id = UUID(request.GET.get('group'))
        try:
            group = ChatGroup.objects.get(uid=group_id, group_owner=user)
            group.delete()
            return Response(
                {
                    "status": True,
                    "message": "group deleted successfully.",
                    "data": {}
                }
            )
        except ChatGroup.DoesNotExist:
            return Response(
                {
                    "status": False,
                    "message": "group not found or you do not have permission to delete this group.",
                    "data": {}
                }
            )


class ListGroupsAPI(generics.ListAPIView):
    # Just fetches groups the user belongs to.
    # Query + serialize, fine inline.
    # But careful: if you serialize nested members/files, it could blow up in N+1 queries.
    # Prefetch related objects (group_members, owner).

    permission_classes = [IsAuthenticated]
    serializer_class = GroupSerialiazer
    queryset = ChatGroup.objects.all()

    def get_queryset(self):
        user = self.request.user
        return self.queryset.filter(group_members__member=user)

    def get(self, request):
        try:
            queryset = self.get_queryset()
            serializer = self.serializer_class(queryset, many=True)
            data = serializer.data
            return Response(
                {
                    "status": True,
                    "message": "Info : groups fetched.",
                    "data": data
                }
            )
        except Exception as e:
            logger.error(f"an unexpected error occurred while listing joined groups: {e}")
            return Response(
                {
                    "status": False,
                    "message": "something went wrong.",
                    "data": {}
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class MemberAPI(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Returns members of a group. Basic query, fine inline.

        group_id = request.GET.get("group")
        if not group_id:
            logger.error("error: group_id not provided")
            return Response(
                {
                    "status": False,
                    "message": "error: group_id not provided.",
                    "data": {}
                }
            )
        try:
            group = ChatGroup.objects.get(uid=UUID(group_id), group_members__member=request.user)
            members = Member.objects.filter(group=group)

            serializer = MemberSerializer(members, many=True)
            return Response(
                {
                    "status": True,
                    "message": "Members fetched.",
                    "data": {
                        "members": serializer.data
                    }
                }
            )
        except ChatGroup.DoesNotExist:
            logger.error("error: invalid group id provided.")
            return Response(
                {
                    "status": False,
                    "message": "Group does not exists.",
                    "data": {}
                }
            )

        except Exception as e:
            logger.error(f"an unexpected error occurred while getting members: {e}")
            return Response(
                {
                    "status": False,
                    "message": "something went wrong.",
                    "data": {}
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def post(self, request):
        # Adds members. Loop over user IDs, one insert per user.
        # This will blow up for bulk adds. Use bulk_create for performance.
        # If you’re notifying new members via email/WS, push that to Celery.

        user_model = get_user_model()
        try:
            data = request.data
            group_id = data.get("groupId")
            if group_id:
                group_uid = UUID(group_id)
            else:
                logger.error("group id not provided!")
                return Response(
                    {
                        "status": False,
                        "message": "group id not provided.",
                        "data": {}
                    }
                )
            try:
                group = ChatGroup.objects.get(
                    uid=group_uid,
                    group_members__member=request.user,
                    group_members__role='admin'
                )
            except ChatGroup.DoesNotExist:
                return Response(
                    {
                        "status": False,
                        "message": "Group does not exist or you don't have admin rights.",
                        "data": {}
                    }
                )

            user_ids_list = data.get("memberId")

            for user_id in user_ids_list:
                user = user_model.objects.get(id=user_id)
                member = Member.objects.create(member=user, group=group)
                serializer = MemberSerializer(member)
                logger.info(f"Added member {user.pk} in group.")
            logger.info("Successfully added members in group.")
            return Response(
                {
                    "status": True,
                    "message": "members added to group.",
                    "data": serializer.data
                }
            )
        except user_model.DoesNotExist:
            return Response(
                {
                    "status": False,
                    "message": "User does not exists.",
                    "data": {}
                }
            )
        except Exception as e:
            logger.error(f"An unexpected error occured: {e}")
            return Response(
                {
                    "status": False,
                    "message": "something went wrong.",
                    "data": {}
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def patch(self, request):
        # Change member role. Single update. Fine inline.
        data = request.data
        group_id = data.get('groupId')
        member_id = data.get('memberId')
        new_role = data.get('newRole')

        try:
            if group_id and member_id and new_role:
                is_admin = Member.objects.filter(group__uid=UUID(group_id), member__id=request.user.id, role="admin").exists()
                if is_admin:
                    try:
                        member = Member.objects.get(group__uid=UUID(group_id), uid=UUID(member_id))
                        member.role=new_role
                        member.save()
                        return Response(
                            {
                                "status": True,
                                "message": "member updated.",
                                "data": {}
                            }
                        )
                    except Member.DoesNotExist:
                        return Response(
                            {
                                "status": False,
                                "message": "The member you are trying to update not exists in group. if you still see them, please wait or reload.",
                                "data": {}
                            }, status=404
                        )
                return Response(
                        {
                            "status": False,
                            "message": "You are not authorized to perform this action.",
                            "data": {}
                        }, status=400
                    )
            return Response(
                {
                    "status": False,
                    "message": "internal server error. Data not recived. Please try again.",
                    "data": {}
                }, status=404
            )

        except Exception as e:
            logger.error(f"An unexpected error occured: {e}")
            return Response(
                {
                    "status": False,
                    "message": "something went wrong while updating member info.",
                    "data": {}
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
    
    def delete(self, request):
        data = request.GET
        group_id = data.get("group")
        member_id = data.get("member")
        try:
            if group_id and member_id:
                is_admin = Member.objects.filter(member__id=request.user.id, role="admin").exists()
                if is_admin:
                    member = Member.objects.filter(uid=UUID(member_id), group__uid=UUID(group_id))
                    if member.exists():
                        member[0].delete()
                        return Response(
                            {
                                "status": True,
                                "message": "success removed member.",
                                "data": {
                                    "memberId": member_id
                                }
                            }
                        )
                    return Response(
                        {
                            "status": False,
                            "message": "The member you are trying to remove does not exists in group. if you still see them, please wait or reload.",
                            "data": {}
                        }, status=404
                    )
                return Response(
                    {
                        "status": False,
                        "message": "You are not authorized to perform this action.",
                        "data": {}
                    }, status=400
                )
            return Response(
                {
                    "status": False,
                    "message": "internal server error. Data not recived. Please try again.",
                    "data": {}
                }, status=404
            )

        except Exception as e:
            logger.error(f"An unexpected error occured: {e}")
            return Response(
                {
                    "status": False,
                    "message": "something went wrong while removing member.",
                    "data": {}
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class MessageAPI(generics.ListAPIView):
    # Returns messages for a group, ordered.
    # This is the hot path. Optimize with select_related (sender, group).
    # Pagination required (don’t return 10k messages).
    # No Celery here, it’s read-only.
    permission_classes = [IsAuthenticated, IsMember]
    queryset = GroupChat.objects.all()
    serializer_class = ChatSerializer

    def get_queryset(self):
        group_id = UUID(self.request.GET.get("group"))
        return self.queryset.filter(group__uid=group_id).exclude(deleted_for=self.request.user).order_by("created_at")


class DeleteMessageApi(generics.DestroyAPIView):
    permission_classes = [IsAuthenticated, IsMember]
    queryset = GroupChat.objects.all()
    serializer_class = ChatSerializer
    lookup_field = "uid"

    def destroy(self, request, *args, **kwargs):
        try:
            instance = self.get_object()  # uses lookup_field
        except Exception:
            return Response(
                {"status": False, "message": "message not found.", "data": {}},
                status=status.HTTP_404_NOT_FOUND,
            )

        user = request.user

        # If requester is the sender -> allow hard delete for everyone
        if getattr(instance.sent_by, "id", None) == getattr(user, "id", None):
            instance.delete()
            return Response(
                {"status": True, "message": "message deleted for everyone.", "data": {}},
                status=status.HTTP_200_OK,
            )

        # Otherwise soft-delete for requester only (assumes deleted_for is M2M to user)
        try:
            instance.deleted_for.add(user)
            return Response(
                {"status": True, "message": "message deleted for you.", "data": {}},
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            logger.exception(f"failed to mark message {instance.uid} deleted_for {user.id}: {e}")
            return Response(
                {"status": False, "message": "could not delete message.", "data": {}},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
    

class ClearAllMessages(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def delete(self, request):
        group_id = request.GET.get("group")
        if not group_id:
            return Response(
                {"status": False, "message": "group_id not provided.", "data": {}},
                status=400,
            )

        try:
            # ensure the requester is a member of the group
            group = ChatGroup.objects.get(uid=UUID(group_id), group_members__member=request.user)
        except ValueError:
            return Response(
                {"status": False, "message": "invalid group id format.", "data": {}},
                status=400,
            )
        except ChatGroup.DoesNotExist:
            return Response(
                {"status": False, "message": "group not found or you are not a member.", "data": {}},
                status=404,
            )

        try:
            # Soft-delete for the requester: mark messages they did NOT send as deleted_for=request.user
            msgs_to_mark = GroupChat.objects.filter(group=group).exclude(sent_by=request.user).exclude(deleted_for=request.user)
            count = msgs_to_mark.count()
            for m in msgs_to_mark:
                m.deleted_for.add(request.user)

            return Response(
                {
                    "status": True,
                    "message": "Messages cleared for you.",
                    "data": {"cleared_count": count},
                }
            )
        except Exception as e:
            logger.exception(f"failed to clear messages for group {group_id}: {e}")
            return Response(
                {"status": False, "message": "something went wrong.", "data": {}},
                status=500,
            )


class RefreshApi(APIView):
    # Dummy api for realtime.
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(
            {
            "status": True,
            "message": "token refreshed",
            "data": {}
        }
        )


class RequestApiView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        group_id = request.GET.get("group")
        if group_id:
            requests = JoinRequest.objects.filter(group__uid=UUID(group_id), group__group_owner__id=request.user.id)
            serializer = RequestSerializer(requests, many=True)
            
            return Response(
                {
                    "status": True,
                    "message": "requests fetched.",
                    "data": serializer.data
                }
            )
        logger.error("group id not provided in get request.")
        return Response(
            {
                "status": False,
                "message": "group_id not provided.",
                "data": {}
            }, status=400
        )
            
    def post(self, request):
        UserModel = get_user_model()
        try:
            group_id = request.data.get("groupId")
            sender = UserModel.objects.get(pk=request.user.id)
            if group_id:
                group = ChatGroup.objects.get(uid=UUID(group_id))
                join_request = JoinRequest.objects.create(
                    sender=sender,
                    group=group
                )
                serializer = RequestSerializer(join_request)
                return Response(
                    {
                        "status": True,
                        "message": "request sent success fully.",
                        "data": serializer.data
                    }
                )
            logger.log("no group id")
            return Response(
                {
                    "status": False,
                    "message": "group_id not provided.",
                    "data": {}
                }, status=400
            )
        except ChatGroup.DoesNotExist:
            logger.error(f"An unexpected error occured: {e}")
            return Response(
                {
                    "status": False,
                    "message": "group not found",
                    "data": {}
                }, status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"An unexpected error occured: {e}")
            return Response(
                {
                    "status": False,
                    "message": "something went wrong while sending request.",
                    "data": {}
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def delete(self, request):
        request_id = request.GET.get("requestId")
        delete_all = request.GET.get("deleteAll")
        group_id = request.GET.get("groupId")
        if request_id:
            try:
                join_request = JoinRequest.objects.get(uid=UUID(request_id))
                join_request.delete()
                return Response(
                    {
                        "status": True,
                        "message": "reqeust deleted successfully.",
                        "data": {
                            "requestId": request_id
                        }
                    }
                )
            except JoinRequest.DoesNotExist:
                return Response(
                    {
                        "status": False,
                        "message": "request not found.",
                        "data": {}
                    }, status=404
                )
        if delete_all and group_id:
            join_requests = JoinRequest.objects.filter(group__uid=UUID(group_id))
            if join_requests.exists():
                join_requests.delete()
                return Response(
                    {
                        {
                        "status": True,
                        "message": "requests deleted successfully.",
                        "data": {}
                    }
                    }
                )
            return Response(
                    {
                        "status": False,
                        "message": "requests not found.",
                        "data": {}
                    }, status=404
                )
        logger.warning("data not provided.")
        return Response(
            {
                "status": False,
                "message": "data not provided.",
                "data": {}
            }, status=400
        )


class FileUpload(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            file = File.objects.create(
                file=request.FILES.get("file"),
                uploaded_by=request.user
            )

            if file:
                return Response(
                    {
                        "status": True,
                        "message": "File uploaded successfully.",
                        "data": {
                            "file_url": file.file.url
                        }
                    }
                )
            return Response(
                {
                    "status": False,
                    "message": "File upload failed.",
                    "data": {}
                }, status=400
            )
        except Exception as e:
            logger.error(f"An unexpected error occured: {e}")
            return Response(
                {
                    "status": False,
                    "message": "something went wrong while uploading file.",
                    "data": {}
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
