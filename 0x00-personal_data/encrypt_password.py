#!/usr/bin/env python3
"""
Implementing the hash_password function to expect one string
argument name password and will return a salted, hashed password,
which is a byte string.

Using the bcrypt package to perform hashing (with hashpw)
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """
    Taking in a password to hash and returing a salted
    byte string.
    """
    password = bytes(password, 'utf-8')
    hashed = bcrypt.hashpw(password, bcrypt.gensalt())

    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Validating if provided password is a match to the hashed password
    """
    if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
        return True
    else:
        return False
