#!/usr/bin/env python3
""" A route module for API """
from flask import Flask, jsonify, request, abort, redirect, url_for
from sqlalchemy.orm.exc import NoResultFound

from auth import Auth


app = Flask(__name__)
AUTH = Auth()


@app.route('/', methods=['GET'], strict_slashes=False)
def index() -> str:
    """ GET 
    Return:
      - JSON payload
    """
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'], strict_slashes=False)
def users() -> str:
    """ POST: Register a new user with the email and password in the x-www-form-urlencoded request,
    It also finds out if a user already has an existing registration  on email provided
    Return:
      - JSON payload
    """

    """ form-data uses request.form, body JSON uses request.get_json() """
    form_data = request.form

    if "email" not in form_data:
        return jsonify({"message": "input email"}), 400
    elif "password" not in form_data:
        return jsonify({"message": "input password"}), 400
    else:

        email = request.form.get("email")
        paswd = request.form.get("password")

        try:
            new_user = AUTH.register_user(email, paswd)
            return jsonify({
                "email": new_user.email,
                "message": "user created"
            })
        except ValueError:
            return jsonify({"message": " existing registration"}), 400


@app.route('/sessions', methods=['POST'], strict_slashes=False)
def login() -> str:
    """ POST: will create a new session for the user, stores as cookie
    Email and paswd fields in x-www-form-urlencoded request
    Return:
      - JSON payload
    """
    form_data = request.form

    if "email" not in form_data:
        return jsonify({"message": "input email"}), 400
    elif "password" not in form_data:
        return jsonify({"message": "input password"}), 400
    else:

        email = request.form.get("email")
        paswd = request.form.get("password")

        if AUTH.valid_login(email, paswd) is False:
            abort(401)
        else:
            session_id = AUTH.create_session(email)
            response = jsonify({
                "email": email,
                "message": "logged in"
                })
            response.set_cookie('session_id', session_id)

            return response


@app.route('/sessions', methods=['DELETE'], strict_slashes=False)
def logout() -> None:
    """ DELETE: This destroys a session by finding session_id (key in cookie)
    Return:
      - Redirect user to status route (GET /)
    """
    session_id = request.cookies.get('session_id')
    if session_id:
        user = AUTH.get_user_from_session_id(session_id)
        if user:
            AUTH.destroy_session(user.id)
            return redirect(url_for('index'))
    else:
        abort(403)


@app.route('/profile', methods=['GET'], strict_slashes=False)
def profile() -> str:
    """ GET /profile
    Finds user's info by finding session_id (key in cookie)
    Return:
      - JSON payload
    """
    session_id = request.cookies.get('session_id')
    if session_id:
        try:
            user = AUTH.get_user_from_session_id(session_id)
            if user:
                return jsonify({"email": user.email}), 200
            else:
                abort(403)
        except NoResultFound:
            abort(403)
    else:
        abort(403)


@app.route('/reset_password', methods=['POST'], strict_slashes=False)
def get_reset_password_token() -> str:
    """ POST /reset_password
    Generates pswd reset token
    Email field in x-www-form-urlencoded request
    Return:
      - JSON payload
    """
    form_data = request.form

    if "email" not in form_data:
        return jsonify({"message": "email required"}), 400
    else:

        email = request.form.get("email")

        try:
            reset_token = AUTH.get_reset_password_token(email)
            return jsonify({
                "email": email,
                "resetn": reset_token
            }), 200
        except ValueError:
            abort(403)


@app.route('/reset_password', methods=['PUT'], strict_slashes=False)
def update_password() -> str:
    """ PUT /reset_password
    Updates user password
    Email, reset_token and new_password fields in x-www-form-urlencoded request
    Return:
      - JSON payload
    """
    form_data = request.form

    if "email" not in form_data:
        return jsonify({"message": "input email"}), 400
    if "reset_token" not in form_data:
        return jsonify({"message": "input password resetn"}), 400
    if "new_password" not in form_data:
        return jsonify({"message": "create new_password"}), 400
    else:

        email = request.form.get("email")
        resetn = request.form.get("resetn")
        new_paswd = request.form.get("new_password")

        try:
            AUTH.update_password(resetn, new_paswd)
            return jsonify({
                "email": email,
                "message": "Login Password updated"
            }), 200
        except ValueError:
            abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
