from flask import Flask, abort, jsonify, url_for, render_template, g, request
from flask.json import JSONEncoder
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
import decimal
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'geunyeorang cheoeum daehoa sijag hajamaja'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://ruvadmin:ge9BQ7fT8bVBgm1B@localhost/ruvapp'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)
auth = HTTPBasicAuth()


class MJSONEncoder(JSONEncoder):

    def default(self, obj):
        if isinstance(obj, decimal.Decimal):
            # Convert decimal instances to strings.
            return str(obj)
        return super(MJSONEncoder, self).default(obj)


app.json_encoder = MJSONEncoder


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True)
    password_hash = db.Column(db.String(128))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)
        print(self.password_hash)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        print '48 - ' + token
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None  # valid token, but expired
        except BadSignature:
            return None  # invalid token
        user = User.query.get(data['id'])
        if user is None:
            return
        return user


class Roof(db.Model):
    __tablename__ = "roofs"
    id = db.Column(db.Integer, primary_key=True)
    length = db.Column(db.DECIMAL(10, 3))
    width = db.Column(db.DECIMAL(10, 3))
    slope = db.Column(db.Float)
    price = db.Column(db.DECIMAL(10, 2))
    address = db.Column(db.VARCHAR(255))

    def serialize(self):
        return {
            'id': self.id,
            'address': self.address,
            'price': self.price,
        }


@auth.verify_password
def verify_password(email_or_token, password):
    # first try to authenticate by token
    user = User.verify_auth_token(email_or_token)
    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(email=email_or_token).first()
        print '86'
        print user
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['POST'])
def login():
    if request.headers['content-Type'] == 'application/x-www-form-urlencoded':
        email = request.form['email']
        password = request.form['password']
        if email is None or password is None:
            abort(400)
        if User.query.filter_by(email=email).first() is not None:
            verify = verify_password(email, password)
            user = User(email=email)
            print('108 - ' + verify)
            if verify:
                print('You already in there\n')
                return render_template('success.html')
            else:
                print 'Login failed'
                return 'Login failed'

        user = User(email=email)
        User.hash_password(user, password)
        db.session.add(user)
        db.session.commit()
        return render_template('success.html')
    elif request.headers['Content-Type'] == 'application/json':
        print '122'
        print(request.json)
        email = request.json.get('email')
        password = request.json.get('password')
        if email is None or password is None:
            abort(400)
        if User.query.filter_by(email=email).first() is not None:
            verify = verify_password(email, password)
            user = User(email=email)
            print '130'
            print verify
            if verify:
                print('132 - You already in there\n')
                return render_template('success.html')
            else:
                print 'Login failed'
                return 'Login failed'

        user = User(email=email)
        User.hash_password(user, password)
        db.session.add(user)
        db.session.commit()
        verify_password(email, password)
        token = g.user.generate_auth_token(600)
        return jsonify({'email': user.email, 'authToken': token.decode('ascii')}), 201, {'Location': url_for('get_user', id=user.id, _external=True)}


@app.route('/roof/add', methods=['POST'])
@auth.login_required
def add_roof():
    print 'Requesting roof addition'
    if request.headers['Content-Type'] == 'application/json':
        print '155'
        print request.json
        length = request.json.get('length')
        width = request.json.get('width')
        slope = request.json.get('slope')
        address = request.json.get('address')
        price = request.json.get('price')

        if length is None or width is None or slope is None or address is None or price is None:
            print 'Something not set'
            abort(400)
        if Roof.query.filter_by(address=address).first() is not None:
            roof = Roof(address=address, price=price)
            print 'Found a roof'
            if roof is not None:
                print 'Roof is not None'
                print str(roof.serialize())
                return jsonify({'Roof': roof.serialize()}), 201
        print 'Make new roof'
        roof = Roof(address=address, length=length, width=width, slope=slope, price=price)
        db.session.add(roof)
        db.session.commit()
        print 'Created roof==> ' + str(roof.serialize())
        return jsonify({'Roof': roof.serialize()}), 201, {
            'Location': url_for('get_roof', address=roof.address, _external=True)}


@app.route('/users/<int:id>')
@auth.login_required
def get_user(id):
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'email': user.email, 'password': user.password_hash})


@app.route('/roofs/<string:address>')
@auth.login_required
def get_roof(address):
    roof = Roof.query.get(address=address)
    if not roof:
        abort(400)
    return jsonify({'Roof': roof.serialize()})


@app.route('/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(600)
    return jsonify({'token': token.decode('ascii'), 'duration': 600})


@app.route('/resource')
@auth.login_required
def get_resource():
    return jsonify({'data': 'Hello, %s!' % g.user.email})


if __name__ == '__main__':
    app.debug = True
    app.run()
