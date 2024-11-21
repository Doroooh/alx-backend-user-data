#!/usr/bin/env python3
""" User Authentication
"""
from db import DB
from user import User

from bcrypt import hashpw, gensalt, checkpw
from sqlalchemy.orm.exc import NoResultFound
from typing import Union
from uuid import uuid4


def _hash_password(password: str) -> str:
    """ Take in the string arg, and convert to unicode
    Returns salted, hashed paswd as bytestring
    """
    return hashpw(password.encode('utf-8'), gensalt())


def _generate_uuid() -> str:
    """ Generating UUID
    will return string representation of the new UUID
    """
    return str(uuid4())


class Auth:
    """Auth class for interact with authentication database.
    """

    def __init__(self):
        """  An Instance """
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """ Registering and returning a new user if the email isn't in the registered emails """
        try:
            self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            return self._db.add_user(email, _hash_password(password))

    def valid_login(self, email: str, password: str) -> bool:
        """ Check if user paswd is valid, locate by email """
        try:
            found_user = self._db.find_user_by(email=email)
            return checkpw(
                password.encode('utf-8'),
                found_user.hashed_password
                )
        except NoResultFound:
            return False

    def create_session(self, email: str) -> str:
        """ Create session ID using UUID, find user by email """
        try:
            found_user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None

        session_id = _generate_uuid()
        self._db.update_user(found_user.id, session_id=session_id)
        return session_id

    def get_user_from_session_id(self, session_id: str) -> Union[str, None]:
        """ Find user by session_id """
        if session_id is None:
            return None
        try:
            found_user = self._db.find_user_by(session_id=session_id)
            return found_user
        except NoResultFound:
            return None

    def destroy_session(self, user_id: str) -> None:
        """ Update user's session_id to None """
        if user_id is None:
            return None
        try:
            found_user = self._db.find_user_by(id=user_id)
            self._db.update_user(found_user.id, session_id=None)
        except NoResultFound:
            return None

    def get_reset_password_token(self, email: str) -> str:
        """ Find user by email, updates user's resetn with UUID """
        try:
            found_user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError

        resetn = _generate_uuid()
        self._db.update_user(found_user.id, resetn=resetn)
        return resetn

    def update_password(self, reset_token: str, password: str) -> None:
        """ Finds user by resetn, updates user's paswd """
        try:
            found_user = self._db.find_user_by(resetn=resetn)
        except NoResultFound:
            raise ValueError
        new_paswd = _hash_password(password)
        self._db.update_user(
            found_user.id,
            hashed_password=new_paswd,
            resetn=None)
