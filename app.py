import imghdr, os, uuid, jwt, datetime, PIL.Image, requests
from flask import Flask, send_from_directory, send_file, render_template, request, jsonify, make_response, \
    url_for, redirect, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, Boolean
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from werkzeug.utils import secure_filename
from PIL import ImageColor

app = Flask(__name__)

# Base directory path (for the database)
basedir = os.path.abspath(os.path.dirname(__file__))

# All the app configs to use the api
# Database Init
app.config['SQLALCHEMY_DATABASE_URI'] ='sqlite:///' + os.path.join(basedir,'users.db')
# Secret Key which allows for the app to ask for authentication every 30 mins
app.config['SECRET_KEY']='secret-key'
# Allowable upload formats for the images
app.config['UPLOAD_EXTENSIONS'] = ['jpg', 'jpeg', 'png', 'gif']
# Location where all the uploads are stored
app.config['UPLOAD_PATH'] = 'static/uploads'

# Generating secret key
s = URLSafeTimedSerializer('SECRET_KEY')

# Setting the db to the current Flask App
db = SQLAlchemy(app)

# Command for creating the database in the event it doesn't exist
@app.cli.command('dbCreate')
def db_create():
    db.create_all()
    print('Database created')

# Drop the database to delete all the data currently in it
@app.cli.command('dbDrop')
def db_drop():
    db.drop_all()
    print('Database Dropped')

# Seed the database with the test user for testing and maintaining
@app.cli.command('dbSeed')
def db_seed():
    # Hashing 'password' in sha256
    hashed_password=generate_password_hash('password', method='sha256')
    # Test user = userName: 'user', password: 'password'
    testUser=User(userName='user',
                  password=hashed_password,
                  )
    # Add and commit
    db.session.add(testUser)
    db.session.commit()
    print('Seeded')

# User class in the for the table in the database
class User(db.Model):
    id = Column(Integer, primary_key=True)
    userName = Column(String(50), unique=True)
    password = Column(String(50))

# Image class for the table in the database
class Image(db.Model):
    id = Column(Integer, primary_key=True)
    # user_uploaded field allows relating the user to the images they uploaded
    user_uploaded = Column(String(50))
    image_id = Column(String(50), unique=True)
    image_path = Column(String(200))
    # To be filled by the image and colour recognition functions
    image_characteristics = Column(String())
    image_public = Column(Boolean)

# Check if the login cookie credentials are valid to continue with the app
def token_required(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        token = None
        # If there is no token in the cookie show the locked-out template
        if 'token' not in session:
            return render_template('locked-out.jinja2')
        else:
            # If no cookie exists at all show the locked-out template
            if session is None:
                return render_template('locked-out.jinja2')
            # If there is a cookie in the request set the token to the one that exists in the cookie
            if 'cookie' in request.headers:
                token = session['token']
            # If there is no cookie in the request show the locked-out template
            if 'cookie' not in request.headers:
                return render_template('locked-out.jinja2')
            # Try to see if decoding the token with the secret key returns the current user
            try:
                data = jwt.decode(token, app.config['SECRET_KEY'])
                current_user = User.query.filter_by(userName=data['userName']).first()
            # If not, redirect the user to the login page
            except:
                return redirect(url_for('login_page'))

            return f(current_user, *args, **kwargs)
    return decorated

# Function for Validating that the image is one of the acceptable file types
def validate_image(location):
    # If the uploaded filetype is one of the acceptable extensions return True
    if str(imghdr.what(location)) in app.config['UPLOAD_EXTENSIONS']:
        return True
    else:
        return False

# Function for detting the dominant colour in an image for tagging
def get_common_colour(image_file, numcolors=1, resize=150):
    # Look up tables with the rgb colour values and the name
    colours = ((255, 255, 255, "white"),
               (255, 0, 0, "red"),
               (128, 0, 0, "dark red"),
               (0, 255, 0, "green"),
               (28, 122, 53, "dark_green"),
               (192, 192, 192, "grey"),
               (255, 255, 0, "yellow"),
               (209, 171, 0, "dirty_yellow"),
               (0, 66, 189, "dark_blue"),
               (191, 62, 8, "rust_red"),
               (249, 122, 5, "orange"),
               (77, 14, 140, "purple"),
               (12, 122, 225, "blue"),
               (159, 213, 253, "light_blue"),
               (44, 52, 92, "navy_blue"),
               (24, 30, 44, "grey_blue"),
               (250, 240, 230, "linen"))

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

    # Converting the rgb to hex
    for x in range(len(colors)):
        colors[x] = '#%02x%02x%02x' % (colors[x][0], colors[x][1], colors[x][2])

    rgb = ImageColor.getcolor(colors[0], "RGB")

    # Submitting the rgb value of the most common colour to be classified
    return nearest_colour(colours, (rgb[0], rgb[1], rgb[2]))


#Getting the nearest recognized colour from the most dominant
def nearest_colour(subjects, query):
    # Lamda function to get the closest colour by rgb value from the input and the colours dictionary
    return min(subjects, key=lambda subject: sum((s - q) ** 2 for s, q in zip(subject, query)))

# Run through a machine learning classification api to return some characteristics about the image
def get_image_classifcation(image_path):
    api_key = 'acc_630736786df6731'
    api_secret = 'bfe9c3a361d722e78509e34a8eb40826'
    image_file = image_path[1:]
    # Getting the tags of the image
    response = requests.post(
        'https://api.imagga.com/v2/tags',
        auth=(api_key, api_secret),
        files={'image': open(image_file, 'rb')})
    res = (response.json())
    return res

# Login endpoint
@app.route('/api/login', methods=['POST'])
def login():
    # Get the login info from the form on the frontend
    login = request.form
    # See if a user exists in the database with the entered username
    user = User.query.filter_by(userName=login['userName']).first()
    # If no user is found, return an error template
    if not user:
        return render_template('error.jinja2', message="A user with this username doesn't exist", url='login')
    # If a user is found, and the entered password is wrong, return an error template
    if not check_password_hash(user.password,login['password']):
        return render_template('error.jinja2', message="Incorrect password", url='login')
    # If a user is found, and the entered password is correct
    if check_password_hash(user.password,login['password']):
        # Create the token using the username, current time and secret key
        token=jwt.encode({'userName': user.userName,'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        # Put the token in a cookie
        session['token'] = token
        # Redirect to the user endpoint
        redir = redirect(url_for('user'))
        redir.headers['x-access-tokens'] = token
        return redir
    else:
        return render_template('error.jinja2', message="Email or Password Incorrect", url='login')

# Register endpoint
@app.route('/api/register', methods=['POST'])
def register():
    # Get the info from the frontend
    data = request.form
    nameUser = data['userName']
    # Test to see if a user with the specified username already exists
    test = User.query.filter_by(userName=nameUser).first()
    # If a user with that name already exists redirect to an error page
    if test:
        return render_template('error.jinja2', message="A user with this email already exists", url='register')
    # If the entered passwords don't match redirect to an error page
    if data['password'] != data['confirmPassword']:
        return render_template('error.jinja2', message="Passwords do not  match", url='register')
    # Otherwise create the new user
    else:
        # Hash the password using sha256
        hashed_password = generate_password_hash(data['password'], method='sha256')
        new_user = User(
                     userName=data['userName'],
                     password=hashed_password
                     )
        # Add and commit to the database
        db.session.add(new_user)
        db.session.commit()
        # Automatically redirect to the login page
        return redirect(url_for('login_page'))

# Add an image endpoint
@app.route('/api/add', methods=['POST'])
@token_required
def upload_file(current_user):
    # Getting the public/private tags
    if (request.form['perms'] == "public"):
        public = True
    else:
        public = False
    # Since the user can upload more then 1 file at once, go file by file
    for uploaded_file in request.files.getlist('file'):
        # Get the filename and extensions of the uploaded files
        filename = secure_filename(uploaded_file.filename)
        file_ext = os.path.splitext(filename)[1]
        # Replace the filename with a random sequence of numbers for security
        encrypted_name = str(uuid.uuid4())
        # Save the file
        uploaded_file.save(os.path.join(app.config['UPLOAD_PATH'], encrypted_name + file_ext))
        # If the file is not a supported image format return error
        if not validate_image(os.path.join(app.config['UPLOAD_PATH'], encrypted_name + file_ext)):
            return "Invalid File Name"
        # Get the most common colour
        colour = get_common_colour(url_for('static', filename='uploads/' + encrypted_name + file_ext))
        characteristics = colour[3]
        # Get the image classifications from the external API
        classifications = get_image_classifcation(url_for('static', filename='uploads/' + encrypted_name + file_ext))
        # Add the colour and the 3 best suited tags to the characteristics
        for x in range(3):
            characteristics = characteristics + "," + classifications['result']['tags'][x]['tag']['en']
        # Add the image object to the database
        new_image = Image(
            user_uploaded=current_user.userName,
            image_id=encrypted_name,
            image_path='uploads/' + encrypted_name + file_ext,
            image_characteristics=characteristics,
            image_public=public
        )
        # Add and commit to the database
        db.session.add(new_image)
        db.session.commit()
    # Automatic redirect to the main image view
    return redirect(url_for('imageView'))

# Get all images endpoint
@app.route('/api/images', methods=['GET'])
@token_required
def imageView(current_user):
    output = []
    # Get all the private images from the current user
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

    # Get all the public images
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
    else:
        # If no images exist automatically redirect to add images
        return redirect('/api/add')


# Search results endpoint
@app.route('/api/results/<params>', methods=['GET'])
@token_required
def resultsView(current_user, params):
    output = []
    # Get all the parameters searched by
    paramaters = params.split('-')
    # Search all private images
    userImgPrivate = Image.query.filter_by(image_public=False, user_uploaded=current_user.userName).all()
    # If any private images exist
    if userImgPrivate:
        for img in userImgPrivate:
            for param in paramaters:
                # Look for for the parameters in the image characteristics
                if param in img.image_characteristics:
                    imagePriv={}
                    imagePriv['image_public']=img.image_public
                    imagePriv['user_uploaded']=img.user_uploaded
                    imagePriv['image_id'] =img.image_id
                    imagePriv['image_path'] =img.image_path
                    imagePriv['image_characteristics']=img.image_characteristics
                    output.append(imagePriv)
                    break
    # Search all public images
    userImgPublic = Image.query.filter_by(image_public=True).all()
    # If any public images exist
    if userImgPublic:
        for img in userImgPublic:
            for param in paramaters:
                # Look for for the parameters in the image characteristics
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
    else:
        # If no images, redirect to add an image
        return redirect('/api/add')

# Download image endpoint
@app.route('/api/download/<folder>/<path>')
@token_required
def download_image(current_user, folder, path):
    url = 'static/' + folder + '/' + path
    return send_file(url, as_attachment=True)

# Search for an image
@app.route('/api/search')
@token_required
def search_main(current_user):
    return render_template('search.jinja2')

# Search post form endpoint
@app.route('/api/search', methods=['POST'])
@token_required
def search_post(current_user):
    parameters = request.form['params']
    # Replace the commas with '-' to pass in the url
    pass_params = parameters.replace(',','-')
    return redirect(url_for('resultsView', params=pass_params))

# Add image endpoint
@app.route('/api/add')
@token_required
def add(current_user):
    return render_template('add.jinja2', userdata=session['userData'])

# Delete image endpoint
@app.route('/api/delete/<image_id>')
@token_required
def deleteImage(current_user, image_id):
    # Get image from database
    userImage=Image.query.filter_by(image_id=image_id).first()

    if userImage:
        # Delete the file from the file structure
        os.remove("static/" + userImage.image_path)
        # Delete the image from the database
        db.session.delete(userImage)
        db.session.commit()
        # Automatically redirect back to image view
        return redirect(url_for('imageView'))
    # If no image is found
    else:
        return render_template('error-logged-in.jinja2', message="Invalid Image Id", url='imageView', userdata=session['userData'])

# Modify an image permissions endpoint
@app.route('/api/editImage/<image_id>')
@token_required
def editImage(current_user, image_id):
    # Get the image being edited from the database
    imgEdit = Image.query.filter_by(image_id=image_id).first()
    if imgEdit:
        # If you are the user who uploaded this image, then can be changed from public to private
        if current_user.userName == imgEdit.user_uploaded:
            if imgEdit.image_public:
                imgEdit.image_public = False
            else:
                imgEdit.image_public = True
            # Commit to the database
            db.session.commit()
            # Automatically redirect to all images
            return redirect(url_for('imageView'))
        # If you are not the user who uploaded the image give error
        else:
            return render_template('error-logged-in.jinja2', message="You don't have the permissions to edit this image",
                                   url='imageView', userdata=session['userData'])
    else:
        # If this image doesn't exist give error
        return render_template('error-logged-in.jinja2', message="Image doesn't exist", url='imageView', userdata=session['userData'])

# Home page (after login) endpoint
@app.route('/api/home', methods=['GET'])
@token_required
def user(current_user):
    user_data = {}
    user_data['userName'] = current_user.userName
    session['userData'] = user_data

    return render_template('home-logged-in.jinja2', userdata=user_data)

# register page
@app.route('/api/register')
def register_page():
    return render_template('register.jinja2')

# login page
@app.route('/api/login')
def login_page():
    return render_template('login.jinja2')

# logout and delete all the credentials
@app.route('/api/logout')
def logout_page():
    session.pop('token', None)
    session.pop('userData', None)
    return redirect(url_for('home'))

# Home page (not logged in)
@app.route('/')
def home():
    return render_template('home.jinja2')

if __name__ == '__main__':
    app.run(debug=True)