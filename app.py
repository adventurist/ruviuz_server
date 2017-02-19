from flask import Flask, abort, jsonify, url_for, render_template, g, request, send_from_directory
from flask.json import JSONEncoder
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
import decimal, re, os, json, datetime
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)
from werkzeug.utils import secure_filename
from calculate import Calculator

UPLOAD_FOLDER = './ruv_uploads/'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])

app = Flask(__name__)
app.config['SECRET_KEY'] = 'geunyeorang cheoeum daehoa sijag hajamaja'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://ruvadmin:ge9BQ7fT8bVBgm1B@localhost/ruvapp'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['PROPAGATE_EXCEPTIONS'] = True
app._static_folder = os.path.join(app.config['UPLOAD_FOLDER'])

db = SQLAlchemy(app)
auth = HTTPBasicAuth()


class MJSONEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, decimal.Decimal):
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
    address_id = db.Column(db.Integer)
    customer_id = db.Column(db.Integer)
    sections = db.relationship('Section', backref='roof', cascade='all, delete-orphan', lazy='dynamic')

    def serialize(self):
        return {
            'id': self.id,
            'length': re.sub("[^0-9^.]", "", str(self.length)),
            'width': re.sub("[^0-9^.]", "", str(self.width)),
            'slope': re.sub("[^0-9^.]", "", str(self.slope)),
            'price': re.sub("[^0-9^.]", "", str(self.price)),
            'address_id': self.address_id,
            'customer_id': self.customer_id,
            'address': self.address.encode("utf-8"),
        }


class Section(db.Model):
    __tablename__ = "section"
    id = db.Column(db.Integer, primary_key=True)
    length = db.Column(db.DECIMAL(10, 3))
    width = db.Column(db.DECIMAL(10, 3))
    full = db.Column(db.Boolean)
    empty = db.Column(db.DECIMAL(10, 3))
    slope = db.Column(db.Float)
    rid = db.Column(db.Integer, db.ForeignKey('roofs.id'))
    emptytype = db.relationship('EmptyType', backref='section', cascade='all, delete-orphan', lazy='dynamic')

    def serialize(self):
        return {
            'id': self.id,
            'length': re.sub("[^0-9^.]", "", str(self.length)),
            'width': re.sub("[^0-9^.]", "", str(self.width)),
            'slope': re.sub("[^0-9^.]", "", str(self.slope)),
            'empty': re.sub("[^0-9^.]", "", str(self.empty)),
            'full': self.full,
        }


class EmptyType(db.Model):
    __tablename__ = "emptytype"
    id = db.Column(db.Integer, primary_key=True)
    sid = db.Column(db.Integer, db.ForeignKey('section.id'))
    name = db.Column(db.VARCHAR(64))
    area = db.Column(db.Float)

    def serialize(self):
        return {
            'id': self.id,
            'sid': self.sid,
            'name': re.sub("[^0-9^.]", "", str(self.name)),
            'area': re.sub("[^0-9^.]", "", str(self.area)),
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


class Address(db.Model):
    __tablename__ = "address"
    id = db.Column(db.Integer, primary_key=True)
    country = db.Column(db.VARCHAR(64))
    region = db.Column(db.VARCHAR(96))
    city = db.Column(db.VARCHAR(96))
    postal = db.Column(db.VARCHAR(32))
    address = db.Column(db.VARCHAR(255))
    customer_id = db.Column(db.Integer)

    def serialize(self):
        return {
            'id': self.id,
            'country': self.country.encode("utf-8"),
            'region': self.region.encode("utf-8"),
            'city': self.city.encode("utf-8"),
            'postal': self.postal.encode("utf-8"),
            'address': self.address.encode("utf-8"),
        }


class Comment(db.Model):
    __tablename__ = "comment"
    id = db.Column(db.Integer, primary_key=True)
    ruvfid = db.Column(db.Integer)
    entry_date = db.Column(db.TIMESTAMP)
    body = db.Column(db.String(512))
    status = db.Column(db.Integer)

    def serialize(self):
        return {
            'id': self.id,
            'ruvfid': self.ruvfid,
            'entry_date': self.entry_date,
            'body': self.body.encode("utf-8"),
            'status': self.status,
        }


class Customer(db.Model):
    __tablename__ = "customer"
    id = db.Column(db.Integer, primary_key=True)
    prefix = db.Column(db.VARCHAR(3))
    first = db.Column(db.VARCHAR(96))
    last = db.Column(db.VARCHAR(96))
    married = db.Column(db.Boolean(96))
    address_id = db.Column(db.Integer)
    phone = db.Column(db.VARCHAR(20))
    email = db.Column(db.VARCHAR(128))
    referred_by = db.Column(db.Integer)

    def serialize(self):
        return {
            'id': self.id,
            'first': self.first.encode("utf-8"),
            'last': self.last.encode("utf-8"),
            'married': self.married,
            'address_id': self.address_id,
            'phone': self.phone.encode("utf-8"),
            'email': self.email.encode("utf-8"),
            'referred_by': self.referred_by,
        }


@auth.verify_password
def verify_password(email_or_token, password):
    user = User.verify_auth_token(email_or_token)
    if not user:
        user = User.query.filter_by(email=email_or_token).first()
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
        return jsonify({'email': user.email, 'authToken': token.decode('ascii')}), 201, {'Location': url_for('get_user',
                                                                                                             id=user.id,
                                                                                                             _external=True)}


@app.route('/roof/add', methods=['POST'])
@auth.login_required
def add_roof():
    print ('Requesting roof addition')
    if request.headers['Content-Type'] == 'application/json':
        print ('155')
        print request.json
        address = request.json.get('address')
        city = request.json.get('city')
        region = request.json.get('region')
        postal = request.json.get('postal')
        slope = request.json.get('slope')
        price = request.json.get('price')
        firstname = request.json.get('firstName')
        lastname = request.json.get('lastName')
        email = request.json.get('email')
        phone = request.json.get('phone')
        prefix = request.json.get('prefix')

        if slope is None or address is None or price is None or firstname is None:
            print ('Something not set')
            abort(400)
        if Roof.query.filter_by(address=address).first() is not None:
            roof = Address(address=address)
            print ('Found a roof')
            if roof is not None:
                print ('Found a roof at the following address: ')
                # print str(address.serialize())
                # return jsonify({'Address': address.serialize()}), 200
        print ('Make new roof')

        newaddress = None
        newcustomer = Customer(prefix=prefix, first=firstname, last=lastname, email=email, phone=phone)

        try:
            db.session.add(newcustomer)
            db.session.commit()
        except Exception as e:
            print e.message
            return jsonify({'CustomerIssue': 'Fail', 'ErrorDetails': 'Unable to create new customer in database'})

        if newcustomer is not None:
            newaddress = Address(city=city, region=region, postal=postal, country='Canada', address=address)

            try:
                db.session.add(newaddress)
                db.session.commit()
            except Exception as e:
                print e.message
                return jsonify({'AddressIssue': 'Fail', 'ErrorDetails': 'Unable to create new address in database'})

        if newaddress is not None and newcustomer is not None:
            roof = Roof(address=address, slope=slope, price=price, address_id=newaddress.id,
                        customer_id=newcustomer.id)
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
    rfiles = RuvFile.query.filter_by(rid=id, status=1).all()
    rcustomers = Customer.query.filter_by(id=roof.customer_id).all()
    raddresses = Address.query.filter_by(id=roof.address_id).all()
    fstr = '['
    for rfile in rfiles:
        comment = Comment.query.filter_by(ruvfid=rfile.id, status=1).one_or_none()
        fstr += '{"file": "' + rfile.filename + '"'
        if comment is not None:
            fstr += ',"comment":"' + comment.body + '"},'
        else:
            fstr += '},'
    fstr = fstr[:-1] + ']'
    cstr = '['
    for rcustomer in rcustomers:
        cstr += '{"customer": "' + str(rcustomer.id) + '"},'
    cstr = fstr[:-1] + ']'
    astr = '['
    for address in raddresses:
        astr += '{"address": [{"address": "' + address.address + '", {"region": "' + address.region + '", "city": "' \
                + address.city + '", "postal": "' + address.postal + '"]},'
    astr = astr[:-1]
    print roof.serialize()
    print fstr
    if not roof:
        abort(400)
    return jsonify({'Roof': roof.serialize(), 'Files': fstr, 'Customers': cstr, 'Address': astr})


@app.route('/token')
@auth.login_required
def get_auth_token():
    print request
    print request.args
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
            if RuvFile.query.filter_by(rid=rid, status=1).count() >= 3:
                file_unpublish = RuvFile(rid=rid, status=1).first()
                file_unpublish(status=0)
                try:
                    db.session.commit()
                except Exception as e:
                    db.session.rollback()
                    db.session.remove()
                return jsonify({'FileIssue': 'Fail', 'ErrorDetails': 'Unable to unpublish existing file. There are '
                                                                     'currently too many published files. New file '
                                                                     'will not be saved'})
            ruvfile = RuvFile(filename=filename, uri=os.path.join(app.config['UPLOAD_FOLDER'], filename), rid=rid,
                              mime=mime, status=1)
            db.session.add(ruvfile)
            db.session.commit()
            print ('Created file==> ' + str(ruvfile.serialize()))
            return jsonify({'File': ruvfile.serialize()}), 201


@app.route('/section/add', methods=['GET', 'POST'])
@auth.login_required
def create_section():
    if request.method == 'POST':
        if request.headers['Content-Type'] == 'application/json':
            print request.json
            length = request.json.get('length')
            width = request.json.get('width')
            slope = request.json.get('slope')
            missing = request.json.get('missing')
            ruvfid = request.json.get('rid')
            full = True if request.json.get('full') == 1 else False

            if length is None or width is None or slope is None or missing is None or ruvfid is None or full is None:
                print 'Insufficient data to create new section'
                return 'Insufficient data to create new section'
            section = Section.query.filter_by(rid=ruvfid, length=length, width=width, empty=missing, full=full,
                                              slope=slope).first()
            if section is not None:
                print ('Found the same section')
                return jsonify({'Section': section.serialize()}), 202
            print ('Create new section')
            new_section = Section(rid=ruvfid, length=length, width=width, empty=missing, full=full, slope=slope)
            db.session.add(new_section)
            db.session.commit()
            if full == -1:
                earea = request.json.get("missing")
                etype = request.json.get("etype")
                if etype is not None:
                    emptytype = EmptyType(sid=new_section.id, name=etype, area=earea)
                    db.session.add(emptytype)
                    db.session.commit()

            print ('Created section ==> ' + str(new_section.serialize()))
            return jsonify({'Section': new_section.serialize()}), 201


@app.route('/comment/add', methods=['GET', 'POST'])
@auth.login_required
def create_comment():
    if request.method == 'POST':
        if request.headers['Content-Type'] == 'application/json':
            print request.json
            comment_body = request.json.get('comment_body')
            ruvfid = int(request.json.get('ruvfid'))
            entry_date = request.json.get('entry_date')

            if entry_date is None:
                entry_date = ('{:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.now()))
            if comment_body is None or ruvfid is None or entry_date is None:
                return 'Insufficient data to generate comment entry'
            if Comment.query.filter_by(body=comment_body).first() is not None:
                comment = Comment(body=comment_body)
                print ('Found the same comment')
                if comment is not None:
                    if comment.entry_date is None and entry_date is not None:
                        comment.entry_date = entry_date
                        try:
                            db.session.commit()
                            print comment.serialize()
                            return jsonify(
                                {'Update': 'Success', 'Comment': comment.serialize()})
                        except Exception as e:
                            db.session.rollback()
                            db.session.remove()
                            return jsonify({'Update': 'Fail'})
                    print str(comment.serialize())
                    return jsonify({'Comment': comment.serialize()}), 202
            print ('Make new comment')
            new_comment = Comment(body=comment_body, ruvfid=ruvfid, entry_date=entry_date, status=1)
            db.session.add(new_comment)
            db.session.commit()
            print ('Created comment==> ' + str(new_comment.serialize()))
            return jsonify({'Comment': new_comment.serialize()}), 201


@app.route('/roofs/all', methods=['GET'])
@auth.login_required
def get_roofs():
    # TODO reorder roofs with newest first
    roofs = Roof.query.order_by(Roof.id.desc()).limit(20).all()
    mJson = ''
    i = 0
    for roof in roofs:
        mJson += '{"roof":' + str(roof.serialize()).replace("'", '"')
        cQuery = Customer.query.filter_by(id=roof.customer_id)
        fQuery = RuvFile.query.filter_by(rid=roof.id, status=1)
        sQuery = Section.query.filter_by(rid=roof.id)
        # aResult = Address.query.filter_by(id=roof.address_id).one_or_none()
        # if aResult is not None:
        #     mJson += '"address":"' + aResult.serialize() + '",'

        if cQuery.count() > 0:
            cResult = cQuery.first()
            mJson = mJson[:-1]
            mJson += ',"customer":"' + cResult.first + ' ' + cResult.last + '",'
        if sQuery.count() > 0:
            sResult = sQuery.all()
            scount = 0
            mJson = mJson[:-1]
            mJson += ',"sections":['
            for section in sResult:
                mJson += '{"slope":"' + str(section.slope) + '", "length":"' + str(section.length) + '", "width":"' + str(section.width) + '", "full":"' + str(section.full) + '",'
                if section.full == -1:
                    etype = EmptyType.query.filter_by(sid=section.id).one_or_none()
                    if etype is not None:
                        mJson += '"empty":"' + str(etype.area) + '", "etype":"' + etype.name + '"},'
                else:
                    mJson = mJson[:-1] + '},'

                scount += 1
            mJson = mJson[:-1] + '],'
        if fQuery.count() > 0:
            fcount = 0
            fileResult = fQuery.all()
            mJson = mJson[:-1]
            mJson += ',"files":['
            for result in fileResult:
                print result.serialize()
                comment = Comment.query.filter_by(ruvfid=result.id, status=1).one_or_none()
                print (comment)
                mJson += '{"' + str(fcount) + '":"' + str(result.filename) + '"'
                if comment is not None:
                    mJson += ',"comment":"' + comment.body + '"},'
                else:
                    mJson += '},'
                fcount += 1
            mJson = mJson[:-1]
            mJson += ']}'
        else:
            mJson = mJson[:-1] + '}'
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
        files_not_found = '['
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
            for file in files:
                filename = str(file["file"])
                num = str(file["num"])
                print 'Request to add filename to Roof with RID == ' + str(id)
                if RuvFile.query.filter_by(rid=id, filename=filename, status=1).first() is not None:
                    existing_file = RuvFile(rid=id, filename=filename, status=1).first()
                    print 'File not changed for RID==>' + str(id) + '\n with Filename==>' + filename
                    print 'Existing File: ' + existing_file.serialize()
                else:
                    print 'Adding new file for RID==>' + str(id) + '\n with Filename==>' + filename
                    files_not_found += '{"file": "' + filename + '", "num": "' + num + '"},'
                i += 1
            files_not_found = files_not_found[:-1] + ']'

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
            print files_not_found
            return jsonify({'Update': 'Success', 'Roof': roof.serialize(), 'FilesNotFound': files_not_found})
        except Exception as e:
            db.session.rollback()
            db.session.remove()
            return jsonify({'Update': 'Fail'})


@app.route('/files/<path:path>')
def static_file(path):
    print ('Attempting to serve this file: ' + str(path))
    return send_from_directory('ruv_uploads', path)


@app.route('/calculate/<int:ruvid>', methods=['GET', 'POST'])
@auth.login_required
def get_estimate(ruvid):
    calculator = Calculator(ruvid)
    sections = calculator.get_sections()
    total_area = calculator.calculate
    price_estimate = calculator.get_estimate(total_area, Calculator.roof_types.Aluminum)


if __name__ == '__main__':
    app.debug = True
    # app.debug = False
    app.run()
