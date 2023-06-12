from django.shortcuts import render
from rest_framework import status
from rest_framework.generics import CreateAPIView
from django.http import JsonResponse
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from authy.serializers import RegistrationSerializer
from authy.api_response import CustomAPIResponse
from django.contrib.auth.password_validation import *


class Home(APIView):
    # permission_classes = (IsAuthenticated,)

    def get(self, request, *args):
        user_name = request.user
        message = f"Welcome {user_name}"
        status_code = status.HTTP_400_BAD_REQUEST
        code_status = "failed"

        response = CustomAPIResponse(message, status_code, code_status)
        return response.send()


# Create your views here.
class RegisterAPIView(CreateAPIView):
    permission_classes = (AllowAny,)
    serializer_class = RegistrationSerializer

    def post(self, request):
        serializer = self.serializer_class(
            data=request.data, context={"request": request}
        )
        try:
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                message = (
                    "Registration successful."
                    "Please confirm your email to complete set up"
                )
                status_code = status.HTTP_201_CREATED
                code_status = "success"
            else:
                message = serializer.errors
                status_code = status.HTTP_400_BAD_REQUEST
                code_status = "failed"
        except Exception as e:
            message = e.args[0]
            status_code = status.HTTP_400_BAD_REQUEST
            code_status = "failed"

        response = CustomAPIResponse(message, status_code, code_status)
        return response.send()
