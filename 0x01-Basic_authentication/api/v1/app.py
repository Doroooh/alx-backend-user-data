
#!/usr/bin/env python3
"""
API routing module for setting up application endpoints and authentication.
"""

import os
from os import getenv
from typing import Tuple

from flask import Flask, abort, jsonify, request
from flask_cors import CORS, cross_origin

from api.v1.auth.auth import Auth
from api.v1.auth.basic_auth import BasicAuth
from api.v1.views import app_views

# Initialize Flask app and register views
app = Flask(__name__)
app.register_blueprint(app_views)
CORS(app, resources={r"/api/v1/*": {"origins": "*"}})

# Initialize 'auth' to None; this will later hold an instance of an auth class
auth = None

# Set up the authentication method based on the 'AUTH_TYPE' environment variable
# If AUTH_TYPE is set to 'basic_auth', use BasicAuth, otherwise use default Auth
auth_type = getenv('AUTH_TYPE', 'default')
if auth_type == "basic_auth":
    auth = BasicAuth()
else:
    auth = Auth()


@app.errorhandler(404)
def not_found(error) -> str:
    """Handles 404 errors by returning a JSON message."""
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(401)
def unauthorized(error: Exception) -> Tuple[jsonify, int]:
    """Handles 401 Unauthorized errors by returning a JSON message.

    Args:
        error (Exception): The caught error instance.

    Returns:
        Tuple[jsonify, int]: JSON response with an "Unauthorized" message and 401 status.
    """
    return jsonify({"error": "Unauthorized"}), 401


@app.errorhandler(403)
def forbidden(error: Exception) -> Tuple[jsonify, int]:
    """Handles 403 Forbidden errors by returning a JSON message.

    Args:
        error (Exception): The caught error instance.

    Returns:
        Tuple[jsonify, int]: JSON response with a "Forbidden" message and 403 status.
    """
    return jsonify({"error": "Forbidden"}), 403


@app.before_request
def handle_request():
    """
    Intercepts incoming requests to enforce authentication checks.
    """
    # If 'auth' has no assigned instance, bypass authentication checks
    if auth is None:
        return

    # Define paths that bypass authentication
    excluded_paths = ['/api/v1/status/',
                      '/api/v1/unauthorized/',
                      '/api/v1/forbidden/']

    # If the request path is within excluded paths, skip authentication
    if not auth.require_auth(request.path, excluded_paths):
        return

    # Check if the request has an authorization header; if not, trigger a 401 error
    auth_header = auth.authorization_header(request)
    if auth_header is None:
        abort(401)

    # Verify the current user; if not found, trigger a 403 error
    user = auth.current_user(request)
    if user is None:
        abort(403)


# Run the application if this module is the main entry point
if __name__ == "__main__":
    host = getenv("API_HOST", "0.0.0.0")
    port = getenv("API_PORT", "5000")
    app.run(host=host, port=port, debug=True)
