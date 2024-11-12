#!/usr/bin/env python3
"""
Module providing authentication framework.
"""
from typing import List, TypeVar

from flask import request


class Auth():
    """Base template for the authentication systems used in this application.
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Evaluates if a specific path requires authentication based on
        a list of paths excluded from authentication checks.

        Returns True if `path` is None.
        Returns True if `excluded_paths` is None or empty.
        Returns False if `path` is included in `excluded_paths`.
        Ensures paths ending with a / in excluded_paths are recognized as 
        equivalent to paths without a trailing /.

        Args:
            path (str): The incoming request path to evaluate.
            excluded_paths (List[str]): Paths that do not require authentication.

        Returns:
            bool: True if the path needs authentication; False otherwise.
        """
        # If path is not provided, assume authentication is required.
        if not path:
            return True
        # If excluded_paths is missing or empty, assume all paths need authentication.
        if not excluded_paths:
            return True
        # Remove any trailing slash from the path for consistent comparison.
        path = path.rstrip("/")
        # Check if the path matches any excluded path in the list.
        # Loop through each excluded path for comparison.
        for excluded_path in excluded_paths:
            # If an excluded path ends in *, match against the starting substring.
            if excluded_path.endswith("*") and \
                    path.startswith(excluded_path[:-1]):
                # If a wildcard match is found, no authentication is needed.
                return False
            # Check if the path directly matches the excluded path.
            elif path == excluded_path.rstrip("/"):
                # No authentication required if there's an exact match.
                return False
        # Return True if the path isn't excluded and requires authentication.
        return True

    def authorization_header(self, request=None) -> str:
        """Retrieves the Authorization header value from the provided request.

        Args:
            request (request, optional): Flask request object. Defaults to None.

        Returns:
            str: The Authorization header value if present, otherwise None.
        """
        # Return None if request is not supplied.
        # Check for the 'Authorization' header and return its value if present.
        if request is not None:
            return request.headers.get('Authorization', None)
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Method to retrieve the current authenticated user from a request.
        This placeholder function currently returns None.
        The actual implementation of user retrieval will be defined later.

        Args:
            request (request, optional): The request object. Defaults to None.

        Returns:
            TypeVar('User'): The user associated with the request, or None.
        """
        return None
