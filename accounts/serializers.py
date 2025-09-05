from rest_framework import serializers
import re
from django.contrib.auth import get_user_model
User = get_user_model()


class CNFUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'name', 'profile_image']


class UserRegisterSerializer(serializers.Serializer):
    email = serializers.CharField()
    password = serializers.CharField()
    name = serializers.CharField()
    profile_image = serializers.ImageField(required=False, allow_null=True)

    def validate_email(self, email):
        email_regex = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
        if not re.match(email_regex, email):
            raise serializers.ValidationError("Enter a valid email address.")
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError("Account associated with this email already exists.")
        return email

    def validate_name(self, name):
        name_regex = r"^[A-Za-z\s'-]+$"
        if not re.match(name_regex, name):
            raise serializers.ValidationError("Name can only contain letters, spaces, hyphens, and apostrophes.")
        return name

    def validate_password(self, password):
        # Password must be at least 8 characters, contain a number, a lowercase, an uppercase, and a special character
        password_regex = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]{8,}$'
        if not re.match(password_regex, password):
            raise serializers.ValidationError(
                "Password must be at least 8 characters long and include an uppercase letter, "
                "a lowercase letter, a number, and a special character."
            )
        return password

    def create(self, validated_data):
        user = User.objects.create(
            email=validated_data.get("email"),
            name=validated_data.get("name"),
            profile_image=validated_data.get("profile_image"),
        )

        user.set_password(validated_data.get("password"))
        user.save()
        return user


class UserLoginSerializer(serializers.Serializer):
    email = serializers.CharField()
    password = serializers.CharField()

    def validate(self, data):
        email_regex = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
        if not re.match(email_regex, data['email']):
            raise serializers.ValidationError("Enter a valid email address.")
        if not User.objects.filter(email=data['email']).exists():
            raise serializers.ValidationError("Account associated with this email does not exists.")

        return data
