
from rest_framework import serializers,status
from rest_framework.exceptions import ValidationError
from shared.utility import chech_email_or_phone_number, valid_username
from .models import CustomUser, VIA_EMAIL, VIA_PHONE,CODE_VERIFIED,DONE,PHOTO_DONE,NEW
from django.core.validators import FileExtensionValidator
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from django.db.models import Q

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

        # current_user = CustomUser.objects.filter(username = data.get("username")).first()
        # if current_user:
        #     raise ValidationError(" bu username mavjud")

        if not valid_username(data.get('username')):
            raise ValidationError("Username mukammal emas")
        return data

    def update(self,instance,validate_data):
        instance.first_name = validate_data.get('first_name',instance.first_name)
        instance.last_name = validate_data.get('last_name',instance.last_name)
        instance.username = validate_data.get('username')
        password = validate_data.get('password')
        if password:
            instance.set_password(password)

        if instance.auth_status == CODE_VERIFIED:
            instance.auth_status = DONE

        instance.save()
        return instance

class ImageUserSerializer(serializers.Serializer):
    photo = serializers.ImageField(validators=[FileExtensionValidator(allowed_extensions=['jpg', 'jpeg', 'png'])])

    def update(self, instance, validated_data):
        photo = validated_data.get('photo')
        if photo and instance.auth_status in [DONE,PHOTO_DONE]:
            instance.photo = photo
            instance.auth_status = PHOTO_DONE
            instance.save()
        else:
            raise ValidationError({
                "msg":"Siz hali tuliq ruyxatdan utmagansiz"
            })
        return instance


class LoginSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=123)
    def __init__(self, *args, **kwargs):
        super(LoginSerializer, self).__init__(*args, **kwargs)
        self.fields['user_input'] = serializers.CharField(required=True)
        self.fields['username'] = serializers.CharField(required=False,read_only=True)

    def auth_validate(self,data):
        user_input = data.get('user_input')
        if valid_username(user_input):
            username = user_input
        elif chech_email_or_phone_number(user_input) == 'email':
            user = CustomUser.objects.filter(email__iexact = user_input).first()
            username = user.username
        elif chech_email_or_phone_number(user_input) == 'phone':
            user = CustomUser.objects.filter(phone = user_input).first()
            username = user.username
        elif valid_username(user_input):
            username = user_input
        else:
            raise ValidationError("Siz username/email/phone xato kiritdingiz")

        user = authenticate(username = username,password = data.get('password'))
        if user is None:
            raise ValidationError("Siz notugri login yoki parol kiritdingiz")
        self.user = user


    def validate(self,data):
        self.auth_validate(data)
        refresh_token = RefreshToken.for_user(self.user)
        data = {
            'msg':"Login buldi",
            "access_token": str(refresh_token.access_token),
            "refresh_token": str(refresh_token),
            "status": status.HTTP_200_OK

        }
        return data

class logoutSerializer(serializers.Serializer):
    refresh = serializers.CharField(max_length=450)

class ForgotPasswordSerializer(serializers.Serializer):
    phone_email = serializers.CharField(required=True,write_only=True)

    def auth_validate(self,data):
        user_input = data.get("phone_email")
        user = CustomUser.objects.filter(Q(email__iexact=user_input) | Q(phone_number = user_input)).first()
        if user is None:
            raise ValidationError("Siz notugri email yoki telefon raqam kiritdingiz")


        if user.auth_status in [NEW,CODE_VERIFIED]:
            raise ValidationError("Siz hali tuliq ruyxat utmagansiz")

    def validate(self, data):
        self.auth_validate(data)
        super(ForgotPasswordSerializer,self).validate(data)
        return data

class ResetPasswordSerializer(serializers.Serializer):
    pass