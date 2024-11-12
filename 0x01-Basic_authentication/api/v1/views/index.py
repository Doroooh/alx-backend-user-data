#!/usr/bin/env python3
""" Index view module to handle general API routes.
"""
from flask import jsonify, abort
from api.v1.views import app_views


@app_views.route('/status', methods=['GET'], strict_slashes=False)
def status() -> str:
    """ GET /api/v1/status
    Returns:
      - JSON response with the current API status.
    """
    return jsonify({"status": "OK"})


@app_views.route('/stats/', strict_slashes=False)
def stats() -> str:
    """ GET /api/v1/stats
    Returns:
      - JSON object containing the total count of each data model.
    """
    from models.user import User
    stats = {}
    stats['users'] = User.count()
    return jsonify(stats)


@app_views.route('/unauthorized/', strict_slashes=False, methods=['GET'])
def unauthorized_endpoint() -> None:
    """Simulated endpoint that triggers a 401 Unauthorized error.

    Returns:
        None: Triggers an HTTP 401 error response.
    """
    abort(401)


@app_views.route('/forbidden/', strict_slashes=False, methods=['GET'])
def forbidden_endpoint() -> None:
    """Simulated endpoint that triggers a 403 Forbidden error.

    Returns:
        None: Triggers an HTTP 403 error response.
    """
    abort(403)
