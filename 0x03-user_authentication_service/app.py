#!/usr/bin/env python3
"""this is a  basic flask appl """

from flask import Flask, jsonify, request, abort, redirect, url_for
from auth import Auth


AUTH = Auth()
app = Flask(__name__)


@app.route('/', methods=['GET'], strict_slashes=False)
def index():
    """func for the root route"""
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'], strict_slashes=False)
def users():
    """ func to  handle the credential """
    email = request.form.get('email')
    passwd = request.form.get('password')
    try:
        user = AUTH.register_user(email, passwd)
        return jsonify({
            'email': email,
            'message': 'user created'
        })
    except Exception:
        pass
    return jsonify({"message": "email already registered"}), 400


@app.route('/sessions', methods=['POST'], strict_slashes=False)
def login():
    """func to  handle the credential """
    email = request.form.get('email')
    passwd = request.form.get('password')
    if AUTH.valid_login(email, passwd) is False:
        abort(401)
    sess_id = AUTH.create_session(email)
    resp = jsonify({"email": f"{email}", "message": "logged in"})
    resp.set_cookie('session_id', sess_id)
    return resp


@app.route('/sessions', methods=['DELETE'], strict_slashes=False)
def logout():
    """ func to  handles deletion of session """
    sess_id = request.cookies.get('session_id')
    user = AUTH.get_user_from_session_id(sess_id)
    if not user:
        abort(403)

    AUTH.destroy_session(sess_id)
    return redirect(url_for('index'))


@app.route('/profile', methods=['GET'], strict_slashes=False)
def profile():
    """ a func  for the profill routee"""
    sess_id = request.cookies.get('session_id')
    user = AUTH.get_user_from_session_id(sess_id)
    if not user:
        abort(403)
    return jsonify({"email": user.email})


@app.route('/reset_password', methods=['POST'], strict_slashes=False)
def get_reset_password_token() -> str:
    """ func for pswd reset """
    email = request.form.get('email')
    try:
        token = AUTH.get_reset_password_token(email)
    except Exception:
        abort(403)
    return jsonify({
        'email': email, 'reset_token': token
    })


@app.route('/reset_password', methods=['PUT'], strict_slashes=False)
def update_password() -> str:
    """func to update the profile password """
    email = request.form.get('email')
    r_token = request.form.get('reset_token')
    new_p = request.form.get('new_password')
    try:
        AUTH.update_password(r_token, new_p)
    except Exception:
        abort(403)
    return jsonify({
        'email': email, 'message': 'Password updated'
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000", debug=True)
