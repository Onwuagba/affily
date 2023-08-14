import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import uuid
from urllib.parse import quote, urlencode

import redis
import requests
from django.contrib.auth import get_user_model
from dotenv import load_dotenv
from requests_oauthlib import OAuth1Session
from rest_framework.exceptions import ValidationError
import logging

from common.exceptions import AlreadyExists

load_dotenv()

UserModel = get_user_model()
logger = logging.getLogger("app")


def allowed_providers(provider):
    providers = {"facebook", "twitter", "google"}
    return provider in providers


class GoogleSignIn:
    def google_social_check(self, data):
        access_token = data.get("access_token")
        if not access_token:
            raise ValidationError("access_token is required.")

        url = "https://www.googleapis.com/oauth2/v3/userinfo"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }
        try:
            response = requests.get(url, headers=headers, verify=False)
            print(response.text)
            return response.json()
        except Exception as e:
            logger.error(e)
            if isinstance(e.args[0], str):
                raise ValidationError(e.args[0]) from e
            raise ValidationError("Error logging in with Google") from e

    def save_user_info(self, data):
        response = self.google_social_check(data)
        if not response:
            return ValidationError("Error confirming access with Google")

        if "error_description" in response:
            raise ValidationError(response["error_description"])

        if (
            response.get("email_verified") == True
            and UserModel.objects.filter(email=response.get("email")).exists()
        ):
            raise AlreadyExists("Email account already exists")

        return UserModel.objects.create(
            username=(f"{response.get('given_name')[:4]}_{str(uuid.uuid4())[:8]}"),
            email=response.get("email"),
            first_name=response.get("given_name"),
            last_name=response.get("family_name"),
            is_active=True,
            channel="google",
        )


class TwitterSignIn:
    def __init__(self):
        self.redis_client = redis.StrictRedis(
            host=os.getenv("REDIS_HOST"), port=os.getenv("REDIS_PORT"), db=0
        )

    def generate_random_key(self):
        return secrets.token_hex(16)

    def twitter_social_check(self):
        consumer_key = os.getenv("TWITTER_CONSUMER_KEY")
        consumer_secret = os.getenv("TWITTER_CONSUMER_SECRET")

        # Get request token
        request_token_url = "https://api.twitter.com/oauth/request_token"
        oauth = OAuth1Session(consumer_key, client_secret=consumer_secret)

        try:
            fetch_response = oauth.fetch_request_token(request_token_url)
        except ValueError:
            return ValidationError("Error connecting to Twitter API")

        resource_owner_key = fetch_response.get("oauth_token")
        resource_owner_secret = fetch_response.get("oauth_token_secret")
        print(f"Got OAuth token: {resource_owner_key}")

        # Generate a random key to use as a reference for this token
        reference_key = self.generate_random_key()

        # Tokens temporarily in Redis with an expiration time of 300 seconds
        expiration_time = 300
        self.redis_client.set(reference_key, resource_owner_key, expiration_time)
        self.redis_client.set(
            f"{reference_key}_secret", resource_owner_secret, expiration_time
        )

        # Get authorization
        base_authorization_url = "https://api.twitter.com/oauth/authorize"
        authorization_url = oauth.authorization_url(base_authorization_url)
        return {"url": authorization_url, "reference_key": reference_key}

    def validate_token(self, reference_key, verifier):
        consumer_key = os.getenv("TWITTER_CONSUMER_KEY")
        consumer_secret = os.getenv("TWITTER_CONSUMER_SECRET")

        # Retrieve the resource_owner_key and resource_owner_secret from Redis using the reference key
        resource_owner_key = self.redis_client.get(reference_key).decode("utf-8")
        resource_owner_secret = self.redis_client.get(
            f"{reference_key}_secret"
        ).decode("utf-8")

        if resource_owner_key is None or resource_owner_secret is None:
            return ValidationError("Invalid reference_key")

        params = {
            "include_email": "true",
            "include_entities": "false",
            "skip_status": "true",
        }

        # Get the access token
        access_token_url = "https://api.twitter.com/oauth/access_token"
        oauth = OAuth1Session(
            consumer_key,
            client_secret=consumer_secret,
            resource_owner_key=resource_owner_key,
            resource_owner_secret=resource_owner_secret,
            verifier=verifier,
        )
        oauth_tokens = oauth.fetch_access_token(access_token_url)

        access_token = oauth_tokens["oauth_token"]
        access_token_secret = oauth_tokens["oauth_token_secret"]

        # Make the request
        oauth = OAuth1Session(
            consumer_key,
            client_secret=consumer_secret,
            resource_owner_key=access_token,
            resource_owner_secret=access_token_secret,
        )

        response = oauth.get(
            "https://api.twitter.com/1.1/account/verify_credentials.json",
            params=params,
        )

        if response.status_code != 200:
            raise ValidationError(f"Request returned an error: {response.text}")

        # delete keys from redis
        self.redis_client.delete(reference_key)
        self.redis_client.delete(f"{reference_key}_secret")

        self.save_user_info(response.json())

    def save_user_info(self, response):
        if not response:
            return ValidationError("Error logging in with twitter")

        if UserModel.objects.filter(email=response.get("email")).exists():
            raise AlreadyExists("Email account already exists")

        if UserModel.objects.filter(username=response.get("screen_name")).exists():
            raise AlreadyExists("Username already exists")

        name = str(response.get("name")).split(",")

        return UserModel.objects.create(
            username=response.get("screen_name"),
            email=response.get("email"),
            first_name=name[0],
            last_name=name[1] or name[0],  # incase only one name is used on profile
            is_active=True,
            channel="twitter",
        )


# def generate_twitter_oauth_signature(
#     http_method, base_url, params, consumer_secret, access_token_secret
# ):
#     # Sort parameters by key
#     sorted_params = sorted(params.items(), key=lambda x: x[0])

#     # Concatenate key-value pairs
#     parameter_string = "&".join([f"{quote(k)}={quote(v)}" for k, v in sorted_params])

#     # Concatenate the base URL and parameter string
#     base_string = (
#         f"{http_method.upper()}&{quote(base_url)}&{quote(parameter_string)}"
#     )

#     # Generate a signing key
#     signing_key = f"{quote(consumer_secret)}&{quote(access_token_secret)}"

#     # Generate the signature
#     signature = hmac.new(signing_key.encode(), base_string.encode(), hashlib.sha1)
#     signature = base64.b64encode(signature.digest()).decode()

#     return signature


# def twitter_social_check(data):
#     url = "https://api.twitter.com/1.1/account/verify_credentials.json"
#     access_token = data.get("access_token")
#     access_token_secret = data.get("access_token_secret")
#     nounce = secrets.token_hex(16)

#     if not access_token or not access_token_secret:
#         raise ValidationError("access_token and access_token_secret are required.")

#     # Twitter OAuth 1.0a credentials
#     consumer_key = os.getenv("TWITTER_CONSUMER_KEY")
#     consumer_secret = os.getenv("TWITTER_CONSUMER_SECRET")

#     # Generate a timestamp
#     timestamp = str(int(time.time()))

#     # Generate the OAuth signature
#     params = {
#         "oauth_consumer_key": consumer_key,
#         "oauth_nonce": nounce,
#         "oauth_signature_method": "HMAC-SHA1",
#         "oauth_timestamp": timestamp,
#         "oauth_token": "YOUR_ACCESS_TOKEN",
#         "oauth_version": "1.0",
#     }
#     oauth_signature = generate_twitter_oauth_signature(
#         "GET", url, params, consumer_secret, access_token_secret
#     )

#     # Prepare the Authorization header
#     auth_header = (
#         f'OAuth oauth_consumer_key="{quote(consumer_key)}",'
#         f"oauth_nonce={nounce},"
#         f'oauth_signature="{quote(oauth_signature)}",'
#         'oauth_signature_method="HMAC-SHA1",'
#         f'oauth_timestamp="{str(int(time.time()))}",'
#         f'oauth_token="{quote(access_token)}",'
#         'oauth_version="1.0"'
#     )

#     # Make the authenticated request
#     headers = {"Authorization": auth_header}
#     response = requests.get(url, headers=headers)

#     return response.json() if response.status_code == 200 else None


def facebook_social_check(access_token):
    url = "https://graph.facebook.com/me"
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(url, headers=headers, verify=False)
    print(response.text)
    return response.json() if response.status_code == 200 else None
