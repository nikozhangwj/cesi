from flask import Blueprint, jsonify, session, request, g
from flask_httpauth import HTTPBasicAuth
from decorators import is_user_logged_in, is_admin
from loggers import ActivityLog
from models import User, token_config

auth = Blueprint("auth", __name__)
api_auth = HTTPBasicAuth()
activity = ActivityLog.getInstance()


@auth.route("/token/", methods=["GET"])
@api_auth.login_required
def get_auth_token():
    expiration = token_config['TOKEN_EXPIRATION']
    token = g.user.generate_auth_token(expiration=expiration)
    return jsonify({'token': token.decode('ascii'), 'duration': expiration})


@api_auth.verify_password
def verify_password(username_or_token, password):
    user = User.verify_auth_token(username_or_token)
    if not user:
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


@auth.route("/login/", methods=["POST"])
def login():
    data = request.get_json()
    user_credentials = {}
    invalid_fields = []
    require_fields = ["username", "password"]
    for field in require_fields:
        value = data.get(field)
        if value is None:
            invalid_fields.append(field)

        user_credentials[field] = value

    if invalid_fields:
        return (
            jsonify(
                status="error",
                message="Please enter valid value for '{}' fields".format(
                    ",".join(invalid_fields)
                ),
            ),
            400,
        )

    result = User.verify(user_credentials["username"], user_credentials["password"])
    if not result:
        session.clear()
        return jsonify(status="error", message="Invalid username/password"), 403

    session["username"] = user_credentials["username"]
    session["logged_in"] = True
    activity.logger.info("{} logged in.".format(session["username"]))
    return jsonify(status="success", message="Valid username/password")


@auth.route("/logout/", methods=["POST"])
def logout():
    username = session.get("username")
    if username is None:
        return jsonify(status="error", message="You haven't already entered"), 403

    activity.logger.error("{} logged out".format(username))
    session.clear()
    return jsonify(status="success", message="Logout")
