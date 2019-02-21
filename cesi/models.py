from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from itsdangerous import SignatureExpired, BadSignature
from run import db

# 设置TOKEN密钥和过期时间
token_config = {'TOKEN_EXPIRATION': 6000, 'SECRET': 'you never guess'}


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(16), index=True, unique=True)
    password = db.Column(db.String(120))
    usertype = db.Column(db.Integer)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password, password)

    def is_admin(self):
        return self.usertype == 0

    def is_normal_user(self):
        return self.usertype == 1

    @staticmethod
    def register(username, password, usertype):
        user = User(username=username, usertype=usertype)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return user

    @staticmethod
    def verify(username, password):
        user = User.query.filter_by(username=username).first()
        if not user:
            return None
        return user.verify_password(password)

    @staticmethod
    def update_password(username, new_password):
        user = User.query.filter_by(username=username).first_or_404()
        user.set_password(new_password)
        db.session.commit()

    @staticmethod
    def delete(username):
        user = User.query.filter_by(username=username).first_or_404()
        db.session.delete(user)
        db.session.commit()

    def generate_auth_token(self, expiration=600):
        s = Serializer(token_config['SECRET'], expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(token_config['SECRET'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None  # valid token, but expired
        except BadSignature:
            return None  # invalid token
        user = User.query.get(data['id'])
        return user
