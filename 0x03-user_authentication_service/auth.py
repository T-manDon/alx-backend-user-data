#!/usr/bin/env python3
"""this is the authentificaton module
"""
import bcrypt
from db import DB
from user import User
import uuid


def _hash_password(password: str) -> bytes:
    """func to return the password """
    h_psw = bcrypt.hashpw(bytes(password, 'utf-8'), bcrypt.gensalt(4))
    return h_psw


def _generate_uuid() -> str:
    """ func to return teh uuid4 strin """
    return str(uuid.uuid4())


class Auth:
    """This class interacts auth db
    """

    def __init__(self):
        """ func to initiate teh object """
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """function for the doc stiring"""
        user_exists = False
        try:
            existing_user = self._db.find_user_by(email=email)
            user_exists = True
        except Exception:
            pass
        if user_exists:
            raise ValueError(f"User {email} already exists")
        hashed_passwd = _hash_password(password)
        return self._db.add_user(email=email, hashed_password=hashed_passwd)

    def valid_login(self, email: str, password: str) -> bool:
        """ Func to validate the credent in db """
        try:
            user = self._db.find_user_by(email=email)
            p = bytes(password, 'utf-8')
            if bcrypt.checkpw(p, user.hashed_password):
                return True
            return False
        except Exception:
            return False

    def create_session(self, email: str) -> str:
        """ creates a new session for user with email """
        try:
            user = self._db.find_user_by(email=email)
            s_id = _generate_uuid()
            self._db.update_user(user.id, session_id=s_id)
            return s_id
        except Exception:
            pass

    def get_user_from_session_id(self, session_id: str) -> User:
        """fuc to return session_id """
        if not session_id:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except Exception:
            return None

    def destroy_session(self, user_id: str) -> User:
        """func to rmv the id of the usersession """
        try:
            self._db.update_user(user_id, session_id=None)
        except Exception:
            return None

    def get_reset_password_token(self, email: str) -> str:
        """ func to reset the pwd """
        try:
            user = self._db.find_user_by(email=email)
        except Exception:
            raise ValueError
        token = _generate_uuid()
        self._db.update_user(user.id, reset_token=token)
        return token

    def update_password(self, reset_token: str, password: str) -> None:
        """func to  update pwd """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except Exception:
            raise ValueError
        hashed_p = _hash_password(password)
        self._db.update_user(user.id, hashed_password=hashed_p,
                             reset_token=None)
