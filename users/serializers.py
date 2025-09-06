from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from shared.utility import chech_email_or_phone_number, valid_username
from .models import CustomUser, VIA_EMAIL, VIA_PHONE,CODE_VERIFIED


class SignUpSerializer(serializers.ModelSerializer):
    id = serializers.UUIDField(read_only=True)
    auth_type = serializers.CharField(required=False, read_only=True)
    auth_status = serializers.CharField(required=False, read_only=True)

    def __init__(self, *args, **kwargs):
        super(SignUpSerializer, self).__init__(*args, **kwargs)
        self.fields['email_phone_number'] = serializers.CharField(required=False)

    class Meta:
        model = CustomUser
        fields = ['id', 'auth_type', 'auth_status']


    def create(self, validated_data):
        user = super(SignUpSerializer, self).create(validated_data)
        if user.auth_type == VIA_EMAIL:
            code = user.create_verify_code(VIA_EMAIL)
            # send_email(user.email, code)
            print(f"VIA_EMAIL: {code}")
        elif user.auth_type == VIA_PHONE:
            code = user.create_verify_code(VIA_PHONE)
            # send_email(user.phone_number, code)
            # send_phone_code(user.phone_number, code)
            print(f"VIA_PHONE: {code}")
        user.save()
        return user

    def validate(self, data):
        super(SignUpSerializer, self).validate(data)
        data = self.auth_validate(data)
        return data

    @staticmethod
    def auth_validate(data):
        print(data)
        user_input = str(data.get('email_phone_number')).lower()
        input_type = chech_email_or_phone_number(user_input)
        print(input_type)
        if input_type == "email":
            data = {
                "email": user_input,
                "auth_type": VIA_EMAIL
            }
        elif input_type == "phone":
            data = {
                "phone_number": user_input,
                "auth_type": VIA_PHONE
            }
        else:
            data = {
                'success': False,
                'message': "To'g'ri telefon raqam yoki email kiriting"
            }
            raise ValidationError(data)

        return data

    def validate_email_phone_number(self, value):
        value = value.lower()
        if value and CustomUser.objects.filter(email=value).exists():
            data = {
                "success": False,
                "message": "Bu email allaqachon ma'lumotlar bazasida bor"
            }
            raise ValidationError(data)
        elif value and CustomUser.objects.filter(phone_number=value).exists():
            data = {
                "success": False,
                "message": "Bu telefon raqami allaqachon ma'lumotlar bazasida bor"
            }
            raise ValidationError(data)

        return value

    def to_representation(self, instance):
        data = super(SignUpSerializer, self).to_representation(instance)
        data.update(instance.token())
        return data


class ChangeInfoUserSerializer(serializers.Serializer):
    first_name = serializers.CharField(write_only=True,required=True)
    last_name = serializers.CharField(write_only=True,required=True)
    username = serializers.CharField(write_only=True,required=True)
    password = serializers.CharField(write_only=True,required=True)
    password_confirm = serializers.CharField(write_only=True,required=True)

    def validate(self, data):
        if data.get('password') != data.get('password_confirm'):
            raise ValidationError({"password_confirm": "Parollar mos emas"})

        if not valid_username(data.get('username')):
            raise ValidationError("Username mukammal emas")
        return data

    def update(self,instanse,validate_data):
        instanse.first_name = validate_data.get('first_name',instanse.first_name)
        instanse.last_name = validate_data.get('last_name',instanse.last_name)
        instanse.username = validate_data.get('username')
        instanse.password = validate_data.get('password')
        if instanse.password:
            instanse.set_password(validate_data.get('password'))

        if instanse.auth_type == CODE_VERIFIED:
            instanse.auth_status = DONE

        instanse.save()
        return instanse

class ImageUserSerializer(serializers.ModelSerializer):
    photo = serializers.ImageField(required=False, allow_null=True)

    class Meta:
        model = CustomUser
        fields = ["photo"]

    def update(self, instance, validated_data):
        instance.photo = validated_data.get('photo', instance.photo)
        instance.save()
        return instance