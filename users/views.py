from django.shortcuts import render
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import SignUpSerializer, ChangeInfoUserSerializer, ImageUserSerializer, LoginSerializer,logoutSerializer,ForgotPasswordSerializer
from rest_framework.exceptions import ValidationError
from .models import CustomUser,NEW,CODE_VERIFIED,VIA_EMAIL,VIA_PHONE
from rest_framework.generics import ListCreateAPIView,UpdateAPIView
from rest_framework.permissions import AllowAny,IsAuthenticated
from rest_framework.views import APIView
from datetime import datetime
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.views import TokenObtainPairView
# Create your views here.

class SignUpView(ListCreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = SignUpSerializer
    permission_classes = [AllowAny, ]

class VerifyCodeApiView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self,request,*args,**kwargs):
        code = self.request.data.get('code')
        user = self.request.user

        self.check_verify(user, code)
        data = {
            'success':True,
            'code_status':user.verify_codes.filter(code = code).first().code_status,
            'auth_status':user.auth_status,
            'access_token':user.token()['access'],
            'refresh_token':user.token()['refresh_token']
        }
        return Response(data=data,status=status.HTTP_200_OK)


    @staticmethod
    def check_verify(user,code):
        verify = user.verify_codes.filter(code = code,code_status = False,expiration_time__gte = datetime.now())
        if not verify.exists():
            data = {
                'succes': False,
                'msg':"Kodingiz eskirgan yoki xato"
            }
            raise ValidationError(data)
        else:
            verify.update(code_status = True)

        if user.auth_status == NEW:
            user.auth_status = CODE_VERIFIED
            user.save()

        return True

class GetNewCodeVerify(APIView):
    def get(self,request,*args,**kwargs):
        user = self.request.user
        self.check_verification(user)

        if user.auth_type == VIA_PHONE:
            code = user.create_verify_code(VIA_PHONE)
            #send_to_phone(user.phone,code)
            print(f"VIA_PHONE CODE: {code}")

        elif user.auth_type == VIA_EMAIL:
            code = user.create_verify_code(VIA_EMAIL)
            #send_to_email(user.email,code)
            print(f"VIA_EMAIL CODE: {code}")
        else:
            raise ValidationError("telefon yoki email xato")

        data = {
            'status':status.HTTP_200_OK,
            'msg':"Kod email/phone ga yuborildi",
            'access_token': user.token()['access'],
            'refresh_token': user.token()['refresh_token']
        }
        return Response(data)

    @staticmethod
    def check_verification(user):
        verify = user.verify_codes.filter(expiration_time__gte = datetime.now(),code_status = False)
        if verify.exists():
            data = {
                "msg":"Sizda aktiv kod bor shundan foydalaning",
                "status":status.HTTP_400_BAD_REQUEST
            }
            raise ValidationError(data)

class ChangeInfoUserApi(UpdateAPIView):
    serializer_class = ChangeInfoUserSerializer
    http_method_names = ["put", "patch"]

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        response = super().update(request, *args, **kwargs)
        user = self.get_object()
        response.data = {
            "msg": "Malumotlar yangilandi",
            "auth_status": user.auth_status,
            "status": status.HTTP_200_OK
        }
        return response

    def partial_update(self, request, *args, **kwargs):
        response = super().partial_update(request, *args, **kwargs)
        user = self.get_object()
        response.data = {
            "msg": "Malumotlar yangilandi",
            "auth_status": user.auth_status,
            "status": status.HTTP_200_OK
        }
        return response

class UploadUserImageView(UpdateAPIView):
    serializer_class = ImageUserSerializer
    http_method_names = ["patch"]

    def get_object(self):
        return self.request.user

    def partial_update(self, request, *args, **kwargs):
        super(UploadUserImageView,self).partial_update(request, *args, **kwargs)
        user = request.user

        data = {
            "msg": "Rasm uzgartirildi",
            "auth_status":user.auth_status,
            "refresh_token":user.token()["refresh_token"],
            "access_token": user.token()["access"],
            "status": status.HTTP_200_OK
        }
        return Response(data)



class TokenRefresh(APIView):
    permission_classes = [AllowAny]
    def post(self,request):
        data = request.data
        try:
            token = RefreshToken(data['refresh'])
            return Response({"access":str(token.access_token),'status':status.HTTP_201_CREATED})
        except Exception as e:
            return Response({'error':str(e),'status':status.HTTP_400_BAD_REQUEST})


class LoginApi(TokenObtainPairView):
    serializer_class = LoginSerializer
    permission_classes = [AllowAny]

class LogoutApi(APIView):
    def post(self,request):
        serializer = logoutSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            token = RefreshToken(serializer.data['refresh'])
            token.blacklist()
            return Response({
                'msg':"Siz dasturdan chiqdingiz",
                'status':status.HTTP_200_OK
            })
        except Exception as e:
            raise ValidationError(e)

class ForgotPasswordApi(APIView):
    permission_classes = [AllowAny]
    def post(self,request):
        serializer = ForgotPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({"data":serializer.data})