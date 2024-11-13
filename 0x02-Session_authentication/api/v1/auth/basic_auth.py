#!/usr/bin/env python3
"""Module handling basic authentication processes
"""
import base64
import binascii
from typing import Tuple, TypeVar

from models.user import User

from .auth import Auth


class BasicAuth(Auth):
    """Class for implementing basic authentication logic.

    Args:
        Auth (type): The class inherited from, containing shared methods.
    """

    def extract_base64_authorization_header(
            self, authorization_header: str) -> str:
        """Extracts the Base64 portion of the Authorization header.

        Args:
            authorization_header (str): The complete Authorization header.

        Returns:
            str: The extracted Base64 encoded part, or None if invalid.
        """
        # Check if authorization_header is None or not a string
        if authorization_header is None or not \
                isinstance(authorization_header, str):
            return None
        # Verify if authorization_header begins with "Basic "
        if not authorization_header.startswith("Basic "):
            return None
        # Return the part after "Basic "
        return authorization_header.split("Basic ")[1].strip()

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """Decodes the Base64 string in `base64_authorization_header` and
        returns the decoded text as UTF-8.

        Args:
            base64_authorization_header (str): A Base64 encoded header.

        Returns:
            str: The decoded string, or None if decoding fails.
        """
        # Return None if base64_authorization_header is missing
        if base64_authorization_header is None:
            return None
        # Return None if it's not a string type
        if not isinstance(base64_authorization_header, str):
            return None
        # Attempt to decode and handle any errors that may occur
        try:
            decoded = base64.b64decode(
                base64_authorization_header,
                validate=True
            )
            # Decode the byte data to a UTF-8 string and return it
            return decoded.decode('utf-8')
        except (binascii.Error, UnicodeDecodeError):
            return None

    def extract_user_credentials(self, decoded_header: str) -> Tuple[str, str]:
        """Extracts the user email and password from the decoded header.

        Args:
            decoded_header (str): Decoded Authorization header string.

        Returns:
            Tuple[str, str]: A tuple with the user email and password.
        """
        # Return None, None if decoded_header is None or not a string
        if decoded_header is None or not isinstance(decoded_header, str):
            return None, None
        # Split the decoded string to separate email and password by first ':'
        try:
            email, password = decoded_header.split(':', 1)
        except ValueError:
            return None, None
        # Return the extracted email and password
        return email, password

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """Fetches the User instance based on email and password.

        Args:
            user_email (str): The user's email.
            user_pwd (str): The user's password.

        Returns:
            User: The User instance if authenticated, otherwise None.
        """
        # Return None if either email or password is missing or not a string
        if not all(map(lambda x: isinstance(x, str), (user_email, user_pwd))):
            return None
        try:
            # Look up the user in the database by email
            user = User.search(attributes={'email': user_email})
        except Exception:
            return None
        # Check if user exists in the database
        if not user:
            return None
        # Take the first user from the search result
        user = user[0]
        # Verify if the password is correct
        if not user.is_valid_password(user_pwd):
            return None
        # Return the authenticated User instance
        return user

    def current_user(self, request=None) -> TypeVar('User'):
        """Retrieves the authenticated User for the request.

        Args:
            request (:obj:`Request`, optional): The Flask request object.

        Returns:
            User: The User instance based on the request data.
        """
        # Retrieve the authorization header from the request
        auth_header = self.authorization_header(request)
        # Extract the Base64 portion of the header
        b64_auth_header = self.extract_base64_authorization_header(auth_header)
        # Decode the Base64 encoded section
        dec_header = self.decode_base64_authorization_header(b64_auth_header)
        # Obtain the user's email and password from the decoded header
        user_email, user_pwd = self.extract_user_credentials(dec_header)
        # Return the User instance found using the email and password
        return self.user_object_from_credentials(user_email, user_pwd)
