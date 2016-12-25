from flask import Flask, abort, jsonify, url_for, render_template, g, request, send_from_directory
from flask.json import JSONEncoder
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
import decimal, re, os, json
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = './ruv_uploads/'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])

app = Flask(__name__)
app.config['SECRET_KEY'] = 'geunyeorang cheoeum daehoa sijag hajamaja'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://ruvadmin:ge9BQ7fT8bVBgm1B@localhost/ruvapp'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app._static_folder = os.path.join(app.config['UPLOAD_FOLDER'])

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
        print ('48 - ' + token)
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
            'length': re.sub("[^0-9^.]", "", str(self.length)),
            'width': re.sub("[^0-9^.]", "", str(self.width)),
            'slope': re.sub("[^0-9^.]", "", str(self.slope)),
            'price': re.sub("[^0-9^.]", "", str(self.price)),
            'address': self.address.encode("utf-8"),
        }


class RuvFile(db.Model):
    __tablename__ = "ruvfile"
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.VARCHAR(128))
    uri = db.Column(db.VARCHAR(255))
    mime = db.Column(db.VARCHAR(64))
    rid = db.Column(db.INTEGER)
    status = db.Column(db.INTEGER)

    def serialize(self):
        return {
            'id': self.id,
            'filename': self.filename.encode("utf-8"),
            'uri': self.uri.encode("utf-8"),
            'rid': self.rid,
        }


@auth.verify_password
def verify_password(email_or_token, password):
    # first try to authenticate by token
    user = User.verify_auth_token(email_or_token)
    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(email=email_or_token).first()
        print ('86')
        print (user)
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['POST'])
def login():
    if request.headers['content-Type'] == 'application/x-www-form-urlencoded':
        email = request.form['email']
        password = request.form['password']
        if email is None or password is None:
            return
            abort(400)
        if User.query.filter_by(email=email).first() is not None:
            verify = verify_password(email, password)
            user = User(email=email)
            print('108 - ' + verify)
            if verify:
                print('User found!\n')
                return render_template('success.html')
            else:
                print ('Wrong Password.')
                return 'Wrong Password'

        user = User(email=email)
        User.hash_password(user, password)
        db.session.add(user)
        db.session.commit()
        return render_template('success.html')
    elif request.headers['Content-Type'] == 'application/json':
        print ('122')
        print(request.json)
        email = request.json.get('email')
        password = request.json.get('password')
        if email is None or password is None:
            abort(400, "What you thinking?")
        if User.query.filter_by(email=email).first() is not None:
            verify = verify_password(email, password)
            user = User(email=email)
            print ('130')
            print verify
            if verify:
                print (g.user.id)
                token = g.user.generate_auth_token(600)
                return jsonify({'email': user.email, 'authToken': token.decode('ascii')}), 201, {
                    'Location': url_for('get_user', id=g.user.id, _external=True)}
            else:
                print ('Error: Wrong Password')
                return 'Wrong Password'

        user = User(email=email)
        User.hash_password(user, password)
        db.session.add(user)
        db.session.commit()
        verify_password(email, password)
        token = g.user.generate_auth_token(600)
        print 'New User Created'
        return jsonify({'email': user.email, 'authToken': token.decode('ascii')}), 201, {'Location': url_for('get_user', id=user.id, _external=True)}


@app.route('/roof/add', methods=['POST'])
@auth.login_required
def add_roof():
    print ('Requesting roof addition')
    if request.headers['Content-Type'] == 'application/json':
        print ('155')
        print request.json
        length = request.json.get('length')
        width = request.json.get('width')
        slope = request.json.get('slope')
        address = request.json.get('address')
        price = request.json.get('price')

        if length is None or width is None or slope is None or address is None or price is None:
            print ('Something not set')
            abort(400)
        if Roof.query.filter_by(address=address).first() is not None:
            roof = Roof(address=address, price=price)
            print ('Found a roof')
            if roof is not None:
                print ('Roof is not None')
                print str(roof.serialize())
                return jsonify({'Roof': roof.serialize()}), 201
        print ('Make new roof')
        roof = Roof(address=address, length=length, width=width, slope=slope, price=price)
        db.session.add(roof)
        db.session.commit()
        print ('Created roof==> ' + str(roof.serialize()))
        return jsonify({'Roof': roof.serialize()}), 201, {
            'Location': url_for('get_roof', id=roof.id, _external=True)}


@app.route('/users/<int:id>')
@auth.login_required
def get_user(id):
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'email': user.email, 'password': user.password_hash})


@app.route('/roofs/<int:id>')
@auth.login_required
def get_roof(id):
    roof = Roof.query.get(id)
    rfiles = RuvFile.query.filter_by(rid=id).all()
    fstr = ''
    for rfile in rfiles:
        fstr += str(rfile.serialize())
    print roof.serialize()
    print fstr
    if not roof:
        abort(400)
    return jsonify({'Roof': roof.serialize(), 'Files': fstr})


@app.route('/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(600)
    return jsonify({'token': token.decode('ascii'), 'duration': 600})


@app.route('/resource')
@auth.login_required
def get_resource():
    return jsonify({'data': 'Hello, %s!' % g.user.email})


@app.route('/file/upload', methods=['GET', 'POST'])
@auth.login_required
def send_file():
    if request.method == 'POST':
        print str(request.files)
        print str(request.args)
        print str(request.values)
        print str(request.get_json)
        if 'upload' not in request.files:
            return 'No files in upload request'
        sendfile = request.files['upload']
        print str(sendfile)
        rid = request.form['rid']
        print str(rid)
        if sendfile.filename == '':
            return 'No specific filename'
        if rid is None:
            return 'No Roof ID provided'
        if sendfile and allowed_file(sendfile.filename):
            filename = secure_filename(sendfile.filename)
            mime = sendfile.content_type
            sendfile.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            ruvfile = RuvFile(filename=filename, uri=os.path.join(app.config['UPLOAD_FOLDER'], filename), rid=rid, mime=mime)
            db.session.add(ruvfile)
            db.session.commit()
            print ('Created file==> ' + str(ruvfile.serialize()))
            return jsonify({'File': ruvfile.serialize()}), 201


@app.route('/roofs/all', methods=['GET'])
@auth.login_required
def get_roofs():

    roofs = Roof.query.all()
    # rStr = ''
    mJson = ''
    # rlist = [None] * 10
    i = 0
    for roof in roofs:
        mJson += '{"roof":' + str(roof.serialize()).replace("'", '"')
        fQuery = RuvFile.query.filter_by(rid=roof.id)
        if fQuery.count() > 0:
            fcount = 0
            fileResult = fQuery.all()
            mJson = mJson[:-1]
            mJson += ',"files":['
            for result in fileResult:
                print result
                mJson += '{"' + str(fcount) + '":"' + str(result.filename) + '"},'
                fcount += 1
            mJson = mJson[:-1]
            mJson += ']}'
        mJson += '},'
        i += 1
    mJson = '{"Roofs":[' + str((mJson[:-1])) + ']}'

    if not roofs:
        abort(400)
    print str(mJson.replace('\\"', '"'))
    return (mJson.replace('\\"', '"')), 201


@app.route('/roof/update/<int:id>', methods=['POST'])
@auth.login_required
def update_roof(id):

    if request.headers['Content-Type'] == 'application/json':
        print ('250')
        print request.json
        files_not_found = ''
        files_not_found_array = []
        length = request.json.get('length')
        width = request.json.get('width')
        slope = request.json.get('slope')
        address = request.json.get('address')
        price = request.json.get('price')

        if request.json.get('files') is not None:
            files = request.json.get('files')
            filesjson = jsonify(request.json.get('files'))
            print str(files)
            print str(filesjson)
            i = 0
            for key in files:
                filename = str(files[i]["file"])
                print 'Request to add filename to Roof with RID == ' + str(id)
                if RuvFile.query.filter_by(rid=id, filename=filename).first() is not None:
                    print 'File not changed for RID==>' + str(id) + '\n with Filename==>' + filename
                else:
                    print 'Adding new file for RID==>' + str(id) + '\n with Filename==>' + filename
                    files_not_found += str({i: filename})
                    files_not_found_array.insert(i, {i: filename})
                i += 1

        roof = Roof.query.get(id)
        if not roof:
            abort(400)

        roof.address = address
        roof.length = length
        roof.price = price
        roof.width = width
        roof.slope = slope
        try:
            db.session.commit()
            print str(files_not_found_array)
            print files_not_found
            return jsonify({'Update': 'Success', 'Roof': roof.serialize(), 'FilesNotFound': files_not_found})
        except Exception as e:
            db.session.rollback()
            db.session.remove()
            return jsonify({'Update': 'Fail'})


@app.route('/files/<path:path>')
def static_file(path):
    print ('Attempting to serve this file: ' + str(path))
    # return app.send_static_file(path)
    return send_from_directory('ruv_uploads', path)
    # return app.send_static_file('/var/www/ruviuz/ruv_uploads/ruviuzIMG20161217_140939.jpg')

if __name__ == '__main__':
    app.debug = True
    # app.debug = False
    app.run()
