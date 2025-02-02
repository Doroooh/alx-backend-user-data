#!/usr/bin/env python3
""" Model for the database
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import InvalidRequestError

from user import Base, User


class DB:
    """ database class """

    def __init__(self):
        """ Instance """

        self._engine = create_engine("sqlite:///a.db", echo=False)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self):
        """ Setting up a session """

        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """ Adding user to the database """

        new_user = User(email=email, hashed_password=hashed_password)
        self._session.add(new_user)
        self._session.commit()
        return new_user

    def find_user_by(self, **kwargs) -> User:
        """ Return the first row found in the users table based on keyword args """

        """ Handling an invalid request """
        if not kwargs:
            raise InvalidRequestError

        users_columns = [
            'id',
            'email',
            'hashed_password',
            'session_id',
            'reset_token'
            ]

        for arg in kwargs:
            if arg not in users_columns:
                raise InvalidRequestError

        """ Search table for user """

        search_user = self._session.query(User).filter_by(**kwargs).first()

        if search_user:
            return search_user
        else:
            raise NoResultFound

    def update_user(self, user_id: int, **kwargs) -> None:
        """ Find user record and update attributes """

        user_to_update = self.find_user_by(id=user_id)

        users_columns = [
            'id',
            'email',
            'hashed_password',
            'session_id',
            'reset_token'
            ]

        for w, y in kwargs.items():
            if w in users_columns:
                setattr(user_to_update, w, y)
            else:
                raise ValueError

        self._session.commit()
