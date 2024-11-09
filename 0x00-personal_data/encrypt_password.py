#!/usr/bin/env python3
"""
Defines the  hash_password function for returning the password
"""
import bcrypt
from bcrypt import hashpw


def hash_password(password: str) -> bytes:
    """
    Returns a hashed password
    Args:
        password (str): password to be hashed
    """
    b = password.encode()
    hashed = hashpw(b, bcrypt.gensalt())
    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Check valid password
    Args:
        hashed_password (bytes): hashed password
        password (str): password in string
    Return:
        bool
    """
    return bcrypt.checkpw(password.encode(), hashed_password)
