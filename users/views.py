from django.shortcuts import render
from .serializers import SignUpSerializer
from .models import CustomUser
from rest_framework.generics import ListCreateAPIView
from rest_framework.permissions import AllowAny
# Create your views here.

class SignUpView(ListCreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = SignUpSerializer
    permission_classes = [AllowAny, ]