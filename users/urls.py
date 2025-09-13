from .views import (SignUpView,VerifyCodeApiView,GetNewCodeVerify,ChangeInfoUserApi,TokenRefresh,UploadUserImageView,
                    LoginApi,LogoutApi,ForgotPasswordApi,ResetPasswordApi,UpdatePasswordApi)
from django.urls import path


urlpatterns = [
    path('signup/', SignUpView.as_view()),
    path('code_verify/', VerifyCodeApiView.as_view()),
    path('new_verify/',GetNewCodeVerify.as_view()),
    path('change_info/',ChangeInfoUserApi.as_view()),
    path('token/refresh/',TokenRefresh.as_view()),
    path('image/',UploadUserImageView.as_view()),
    path("login/",LoginApi.as_view()),
    path("logout/", LogoutApi.as_view()),
    path('forgot/',ForgotPasswordApi.as_view()),
    path('reset/',ResetPasswordApi.as_view()),
    path("update/",UpdatePasswordApi.as_view())
]