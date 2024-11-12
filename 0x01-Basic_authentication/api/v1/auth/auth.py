#!/usr/bin/env python3
"""
Create the class Auth:
    in the file api/v1/auth/auth.py
    import request from flask
    class name Auth
    public method:
            def require_auth(self, path: str,
                            excluded_paths: List[str]) -> bool:
        that returns False - path and excluded_paths will be used later,
        now, you don’t need to take care of them
    public method:
            def authorization_header(self, request=None) -> str:
        that returns None - request will be the Flask request object
    public method:
            def current_user(self, request=None) -> TypeVar('User'):
        that returns None - request will be the Flask request object
    This class is the template for authentication system you will implement.
"""
from flask import request
from typing import List, TypeVar


class Auth():
    """See above"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Checking on the file path and authorization"""
        if path is None or excluded_paths is None or excluded_paths == []:
            return True

        if path[-1] != '/':
            path = path + '/'

        for exclp in excluded_paths:
            if exclp[-1] == '*':
                exclp = exclp[0:-1]

            if exclp in path:
                return False

        if path not in excluded_paths:
            return True

        return False

    def authorization_header(self, request=None) -> str:
        """to be added later"""
        if request is None or request.headers.get('Authorization') is None:
            return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Returns none"""
        return None
