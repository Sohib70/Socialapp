from .views import SignUpView,VerifyCodeApiView,GetNewCodeVerify,ChangeInfoUserApi,TokenRefresh,UploadUserImageView
from django.urls import path


urlpatterns = [
    path('signup/', SignUpView.as_view()),
    path('code_verify/', VerifyCodeApiView.as_view()),
    path('new_verify/',GetNewCodeVerify.as_view()),
    path('change_info/',ChangeInfoUserApi.as_view()),
    path('token/refresh/',TokenRefresh.as_view()),
    path('image/',UploadUserImageView.as_view())
]