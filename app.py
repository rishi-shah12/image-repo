import imghdr

from flask import Flask, send_from_directory, send_file
import flask
from flask import Flask,render_template, request, jsonify, make_response, url_for,redirect
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager,jwt_required,create_access_token
from sqlalchemy import Column, Integer,String, Float, Boolean
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import json
import os
import addon
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import requests
from functools import wraps
from flask import Flask, session
from werkzeug.utils import secure_filename
import numpy
import PIL.Image
from PIL import ImageColor
from PIL import ImageDraw
import requests


app = Flask(__name__)

basedir = os.path.abspath(os.path.dirname(__file__)) #Where to store the file for the db (same folder as the running application)

app.config['SQLALCHEMY_DATABASE_URI'] ='sqlite:///' + os.path.join(basedir,'users.db') #initalized db
app.config['SECRET_KEY']='secret-key'
app.config['UPLOAD_EXTENSIONS'] = ['.jpg', 'jpeg', '.png', '.gif']
app.config['UPLOAD_PATH'] = 'static/uploads'

s = URLSafeTimedSerializer('SECRET_KEY')

db=SQLAlchemy(app)
@app.cli.command('dbCreate')
def db_create():
    db.create_all()
    print('Database created')

@app.cli.command('dbDrop')
def db_drop():
    db.drop_all()
    print('Database Dropped')

@app.cli.command('dbSeed')
def db_seed():
    hashed_password=generate_password_hash('password', method='sha256')
    testUser=User(userName='user',
                  password=hashed_password,
                  )
    db.session.add(testUser)
    db.session.commit()
    print('Seeded')


class User(db.Model):
    id = Column(Integer, primary_key=True)
    userName = Column(String(50), unique=True)
    password = Column(String(50))

class Image(db.Model):
    id = Column(Integer, primary_key=True)
    user_uploaded = Column(String(50))
    image_id = Column(String(50), unique=True)
    image_path = Column(String(200))
    image_characteristics = Column(String())
    image_public = Column(Boolean)

def token_required(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        token = None
        if 'token' not in session:
            return render_template('locked-out.jinja2')
        else:
            if session is None:
                return render_template('locked-out.jinja2')
            if 'cookie' in request.headers:
                token=session['token']
            if 'cookie' not in request.headers:
                return jsonify(message='Token is missing'),401
            try:
                data=jwt.decode(token, app.config['SECRET_KEY'])
                current_user=User.query.filter_by(userName=data['userName']).first()
            except:
                return redirect(url_for('login_page'))

            return f(current_user, *args, **kwargs)
    return decorated

def validate_image(stream):
    header = stream.read(512)
    stream.seek(0)
    format = imghdr.what(None, header)
    print(format)
    if format == 'jpeg':
        format = 'jpg'
    if not format:
        return None

    return '.' + format

def get_common_colour(image_file, numcolors=1, resize=150):
    colours = ((255, 255, 255, "white"),
               (255, 0, 0, "red"),
               (128, 0, 0, "dark red"),
               (0, 255, 0, "green"),
               (28, 122, 53, "dark_green"),
               (192, 192, 192, "grey"),
               (255, 255, 0, "yellow"),
               (209, 171, 0, "dirty_yellow"),
               (0, 66, 189, "dark_blue"))

    # Resize image to speed up processing
    img = PIL.Image.open(image_file[1:])
    img = img.copy()
    img.thumbnail((resize, resize))

    # Reduce to palette
    paletted = img.convert('P', palette=PIL.Image.ADAPTIVE, colors=numcolors)

    # Find dominant colors
    palette = paletted.getpalette()
    color_counts = sorted(paletted.getcolors(), reverse=True)
    colors = list()
    for i in range(numcolors):
        palette_index = color_counts[i][1]
        dominant_color = palette[palette_index * 3:palette_index * 3 + 3]
        colors.append(tuple(dominant_color))

    for x in range(len(colors)):
        colors[x] = '#%02x%02x%02x' % (colors[x][0], colors[x][1], colors[x][2])

    rgb = ImageColor.getcolor(colors[0], "RGB")

    return nearest_colour(colours, (rgb[0], rgb[1], rgb[2]))


def nearest_colour( subjects, query ):
    return min( subjects, key = lambda subject: sum( (s - q) ** 2 for s, q in zip( subject, query ) ) )

def get_image_classifcation(image_path):
    api_key = 'acc_630736786df6731'
    api_secret = 'bfe9c3a361d722e78509e34a8eb40826'
    image_file = image_path[1:]
    response = requests.post(
        'https://api.imagga.com/v2/tags',
        auth=(api_key, api_secret),
        files={'image': open(image_file, 'rb')})
    res = (response.json())
    return res

#User Endpoints
@app.route('/api/login', methods=['POST'])
def login():
    login = request.form
    user = User.query.filter_by(userName=login['userName']).first()

    if not user:
        return render_template('error.jinja2', message="A user with this email doesn't exist", url='login')
    if not check_password_hash(user.password,login['password']):
        return render_template('error.jinja2', message="Incorrect password", url='login')
    if check_password_hash(user.password,login['password']): #queried password
        token=jwt.encode({'userName': user.userName,'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        session['token'] = token
        redir = redirect(url_for('user'))
        redir.headers['x-access-tokens'] = token
        return redir
    else:
        return render_template('error.jinja2', message="Email or Password Incorrect", url='login')
@app.route('/api/register', methods=['POST'])
def register():
    data=request.form
    nameUser=data['userName']
    test=User.query.filter_by(userName=nameUser).first()

    if test:
        return render_template('error.jinja2', message="A user with this email already exists", url='register')
    if data['password'] != data['confirmPassword']:
        return render_template('error.jinja2', message="Passwords do not  match", url='register')
    else:
        hashed_password=generate_password_hash(data['password'], method='sha256')
        new_user = User(
                     userName=data['userName'],
                     password=hashed_password
                     )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login_page'))


@app.route('/api/add', methods=['POST'])
@token_required
def upload_file(current_user):
    if (request.form['perms'] == "public"):
        public = True
    else:
        public = False

    for uploaded_file in request.files.getlist('file'):
        filename = secure_filename(uploaded_file.filename)
        file_ext = os.path.splitext(filename)[1]
        print("Main func" + file_ext)
        if file_ext not in app.config['UPLOAD_EXTENSIONS']: #or file_ext != validate_image(uploaded_file.stream):
            return "Invalid File Name"
        encrypted_name = str(uuid.uuid4())
        uploaded_file.save(os.path.join(app.config['UPLOAD_PATH'], encrypted_name + file_ext))
        colour = get_common_colour(url_for('static', filename='uploads/' + encrypted_name + file_ext))
        characteristics = colour[3]
        classifications = get_image_classifcation(url_for('static', filename='uploads/' + encrypted_name + file_ext))
        for x in range(3):
            characteristics = characteristics + "," + classifications['result']['tags'][x]['tag']['en']

        new_image = Image(
            user_uploaded=current_user.userName,
            image_id=encrypted_name,
            image_path='uploads/' + encrypted_name + file_ext,
            image_characteristics=characteristics,
            image_public=public
        )
        db.session.add(new_image)
        db.session.commit()
    return redirect(url_for('imageView'))
    #return jsonify(message='Image(s) Added')

    #return render_template('display.jinja2', name='uploads/'+ encrypted_name + file_ext)

@app.route('/api/images', methods=['GET'])
@token_required
def imageView(current_user):
    output = []
    userImgPrivate = Image.query.filter_by(image_public=False,user_uploaded=current_user.userName).all()
    if userImgPrivate:
        for img in userImgPrivate:
            imagePriv={}
            imagePriv['image_public']=img.image_public
            imagePriv['user_uploaded']=img.user_uploaded
            imagePriv['image_id'] =img.image_id
            imagePriv['image_path'] =img.image_path
            imagePriv['image_characteristics']=img.image_characteristics
            output.append(imagePriv)


    userImgPublic=Image.query.filter_by(image_public=True).all()
    if userImgPublic:
        for img in userImgPublic:
            imagePub={}
            imagePub['image_public'] = img.image_public
            imagePub['user_uploaded']=img.user_uploaded
            imagePub['image_id'] =img.image_id
            imagePub['image_path'] =img.image_path
            imagePub['image_characteristics']=img.image_characteristics
            output.append(imagePub)

        number = len(output)
        return render_template('all-images.jinja2', userdata=session['userData'], number=number, output=output, title="All Images")
        #return jsonify(output)
        #return render_template('portfolio-overview.jinja2', userdata=session['userData'], output=output, number=number)
    else:
        return redirect('/api/add')



@app.route('/api/results/<params>', methods=['GET'])
@token_required
def resultsView(current_user, params):
    output = []
    paramaters = params.split('-')
    print(paramaters)
    userImgPrivate = Image.query.filter_by(image_public=False, user_uploaded=current_user.userName).all()

    if userImgPrivate:
        for img in userImgPrivate:
            for param in paramaters:
                if param in img.image_characteristics:
                    imagePriv={}
                    imagePriv['image_public']=img.image_public
                    imagePriv['user_uploaded']=img.user_uploaded
                    imagePriv['image_id'] =img.image_id
                    imagePriv['image_path'] =img.image_path
                    imagePriv['image_characteristics']=img.image_characteristics
                    output.append(imagePriv)
                    break

    userImgPublic = Image.query.filter_by(image_public=True).all()

    if userImgPublic:
        for img in userImgPublic:
            for param in paramaters:
                if param in img.image_characteristics:
                    imagePub={}
                    imagePub['image_public']=img.image_public
                    imagePub['user_uploaded']=img.user_uploaded
                    imagePub['image_id'] =img.image_id
                    imagePub['image_path'] =img.image_path
                    imagePub['image_characteristics']=img.image_characteristics
                    output.append(imagePub)
                    break

        number = len(output)
        return render_template('all-images.jinja2', userdata=session['userData'], number=number, output=output,
                               title="Image Results for: " + params)
        # return jsonify(output)
        #return render_template('portfolio-overview.jinja2', userdata=session['userData'], output=output, number=number)
    else:
        return redirect('/api/add')

@app.route('/api/download/<folder>/<path>')
@token_required
def download_image(current_user, folder, path):
    print(folder)
    print(path)
    url = 'static/' + folder + '/' + path
    return send_file(url, as_attachment=True)

@app.route('/api/search')
@token_required
def search_main(current_user):
    return render_template('search.jinja2')

@app.route('/api/search', methods=['POST'])
@token_required
def search_post(current_user):
    parameters = request.form['params']
    pass_params = parameters.replace(',','-')
    return redirect(url_for('resultsView', params=pass_params))

@app.route('/api/add')
@token_required
def add(current_user):
    return render_template('add.jinja2', userdata=session['userData'])

@app.route('/api/delete/<image_id>')
@token_required
def deleteImage(current_user, image_id):

    userImage=Image.query.filter_by(image_id=image_id).first()

    if userImage:
        os.remove("static/" + userImage.image_path)
        db.session.delete(userImage)
        db.session.commit()
        return redirect(url_for('imageView'))
    else:
        return render_template('error-logged-in.jinja2', message="Invalid Image Id", url='imageView', userdata=session['userData'])

@app.route('/api/editImage/<image_id>')
@token_required
def editImage(current_user, image_id):
    imgEdit = Image.query.filter_by(image_id=image_id).first()
    if imgEdit:
        if current_user.userName == imgEdit.user_uploaded:
            if imgEdit.image_public:
                imgEdit.image_public = False
            else:
                imgEdit.image_public = True

            db.session.commit()
            return redirect(url_for('imageView'))
        else:
            return render_template('error-logged-in.jinja2', message="You don't have the permissions to edit this image",
                                   url='imageView', userdata=session['userData'])
    else:
        return render_template('error-logged-in.jinja2', message="Image doesn't exist", url='imageView', userdata=session['userData'])


@app.route('/api/home', methods=['GET'])
@token_required
def user(current_user):
    user_data = {}
    user_data['userName'] = current_user.userName
    session['userData'] = user_data

    return render_template('home-logged-in.jinja2', userdata=user_data)

@app.route('/api/register')
def register_page():
    return render_template('register.jinja2')

@app.route('/api/login')
def login_page():
    return render_template('login.jinja2')

@app.route('/api/logout')
def logout_page():
    session.pop('token', None)
    session.pop('userData', None)
    return redirect(url_for('home'))

@app.route('/')
def home():
    return render_template('home.jinja2')
