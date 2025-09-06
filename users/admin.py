from django.contrib import admin
from .models import CustomUser,CodeVerified
# Register your models here.
admin.site.register(CustomUser)
admin.site.register(CodeVerified)