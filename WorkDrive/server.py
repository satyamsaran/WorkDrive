from bson import ObjectId
from flask import Flask
from flask_pymongo import PyMongo
from flask import render_template, request, redirect, session, abort, send_file
from cfg import config
from hashlib import sha256
from datetime import datetime
from utils import get_random_string
import pymongo
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config["MONGO_URI"] = config['mongo_uri']
app.config['UPLOAD_FOLDER'] = '/Users/Satyam Saran/Desktop/WorkDrive/Uploads'
mongo = PyMongo(app)

app.secret_key = b'riarhg3898%^'


@app.route('/')
def show_index():
    if not 'userToken' in session:
        session['error'] = 'You must login to access this page'
        return redirect('/login')
    # validate user token
    token_document = mongo.db.user_tokens.find_one({
        'sessionHash': session['userToken'],
    })

    if token_document is None:
        session.pop('userToken', None)
        session['error'] = 'You must login again to access this page'
        return redirect('/login')

    error = ''
    if 'error' in session:
        error = session['error']
        session.pop('error', None)

    userId = token_document['userId']

    user = mongo.db.users.find_one({
        '_id': userId
    })
    uploaded_files = mongo.db.files.find({
        'userId': userId,
        'isActive': True
    }).sort([("createdAt", pymongo.DESCENDING)])

    return render_template('files.html',
                           uploaded_files=uploaded_files,
                           user=user, error=error)


@app.route('/login')
def show_login():
    if 'userToken' in session:
        # validate user token from database
        pass
    signupSuccess = ''
    if 'signupSuccess' in session:
        signupSuccess = session['signupSuccess']
        session.pop('signupSuccess', None)

    error = ''
    if 'error' in session:
        error = session['error']
        session.pop('error', None)
    return render_template('login.html', signupSuccess=signupSuccess, error=error)


@app.route('/check_login', methods=['POST'])
def check_login():
    try:
        password = request.form['password5']
    except KeyError:
        password = ''

    try:
        email = request.form['email5']
    except KeyError:
        email = ''
    # check if email is blank
    if not len(email) > 0:
        session['error'] = 'Email is required'
        return redirect('/login')

    # check if password is blank
    if not len(password) > 0:
        session['error'] = 'Password is required'
        return redirect('/login')

    # find email in database
    user_document = mongo.db.users.find_one({"email": email})
    if user_document is None:
        # user doc with given email not found
        session['error'] = 'No account exists with this email address'
        return redirect('/login')

    # verify that password hash matches with original
    password_hash = sha256(password.encode('utf-8')).hexdigest()
    if user_document['password'] != password_hash:
        session['error'] = 'Password is wrong'
        return redirect('/login')

    # generate token and save it to session
    random_string = get_random_string()
    randomSessionHash = sha256(random_string.encode('utf-8')).hexdigest()
    token_object = mongo.db.user_tokens.insert_one({
        'userId': user_document['_id'],
        'sessionHash': randomSessionHash,
        'createdAt': datetime.utcnow()
    })

    session['userToken'] = randomSessionHash
    return redirect('/')


@app.route('/signup')
def show_signup():
    error = ''
    if 'error' in session:
        error = session['error']
        session.pop('error', None)

    return render_template('signup.html', error=error)


@app.route('/handle_signup', methods=['POST'])
def handle_signup():
    try:
        password = request.form['password']
    except KeyError:
        password = ''

    try:
        email = request.form['email']
    except KeyError:
        email = ''

    # check if email is blank
    if not len(email) > 0:
        session['error'] = 'Email is required'
        return redirect('/signup')

    # check if email is valid
    if not '@' in email or not '.' in email or ' ' in email:
        session['error'] = 'Email is invalid'
        return redirect('/signup')

    # check if password is blank
    if not len(password) > 0:
        session['error'] = 'Password is required'
        return redirect('/signup')

    # check if password is valid

    # Check if email already exists
    matching_user_count = mongo.db.users.count_documents({"email": email})
    if matching_user_count > 0:
        session['error'] = 'Email already exists'
        return redirect('/signup')

    password = sha256(password.encode('utf-8')).hexdigest()

    # Create user data base
    result = mongo.db.users.insert_one({
        'email': email,
        'password': password,
        'name': '',
        'lastLoginDate': None,
        'createdAt': datetime.utcnow(),
        'updatedAt': datetime.utcnow()
    })
    # redirect to login page
    session['signupSuccess'] = 'Your user account is ready. You can login now'
    return redirect('/login')


@app.route('/logout')
def logout_user():
    session.pop('userToken', None)
    session['signupSuccess'] = 'You are now logged out.'
    return redirect('/login')


def allowed_file(filename):
    ALLOWED_EXTENSIONS = ['jpg', 'jpeg', 'docx', 'gif', 'doc', 'xls', 'xlsx', 'ppt', 'pptx', 'pdf', 'csv']
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/handle_file_upload', methods=['Post'])
def handle_file_upload():
    if not 'userToken' in session:
        session['error'] = 'You must login to access this page'
        return redirect('/login')
    # validate user token
    token_document = mongo.db.user_tokens.find_one({
        'sessionHash': session['userToken'],
    })

    if token_document is None:
        session.pop('userToken', None)
        session['error'] = 'You must login again to access this page'
        return redirect('/login')

    if 'uploadedFile' not in request.files:
        session['error'] = 'No File Uploaded'
        return redirect('/')
    file = request.files['uploadedFile']
    if file.filename == '':
        session['error'] = 'No selected file'
        return redirect('/')
    if not allowed_file(file.filename):
        session['error'] = 'file type not supported'
        return redirect('/')

    # TODO File size check
    extension = file.filename.rsplit('.', 1)[1].lower()
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    result = mongo.db.files.insert_one({
        'userId': token_document['userId'],
        'originalFileName': file.filename,
        'fileType': extension,
        'fileSize': 0,
        'fileHash': '',
        'filePath': filepath,
        'isActive': True,
        'createdAt': datetime.utcnow()
    })
    return redirect('/')
@app.route('/download/<fileId>/<fileNameSlugified>', methods=['GET'])
def showDownloadPage(fileId,fileNameSlugified):
    if not 'userToken' in session:
        session['error'] = 'You must login to access this page'
        return redirect('/login')
    # validate user token
    token_document = mongo.db.user_tokens.find_one({
        'sessionHash': session['userToken'],
    })

    if token_document is None:
        session.pop('userToken', None)
        session['error'] = 'You must login again to access this page'
        return redirect('/login')
    userId = token_document['userId']

    user = mongo.db.users.find_one({
        '_id': userId
    })
    file_object=None
    try:
        file_object = mongo.db.files.find_one({
            '_id': ObjectId(fileId),
        })
    except:
        pass

    if file_object is None:
        return abort(404)
    return render_template('download.html', file=file_object, user=user)

@app.route('/download_file/<fileId>', methods=['GET'])
def downloadFile(fileId):
    if not 'userToken' in session:
        session['error'] = 'You must login to access this page'
        return redirect('/login')
    # validate user token
    token_document = mongo.db.user_tokens.find_one({
        'sessionHash': session['userToken'],
    })

    if token_document is None:
        session.pop('userToken', None)
        session['error'] = 'You must login again to access this page'
        return redirect('/login')
    file_object = None
    try:
        file_object = mongo.db.files.find_one({
            '_id': ObjectId(fileId),
        })
    except:
        pass

    if file_object is None:
        return abort(404)

    #Track user downloads
    userId=token_document['userId']

    mongo.db.file_downloads.insert_one({
        'fileId':file_object['_id'],
        'userId':userId,
        'createdAt':datetime.utcnow()
    })

    filePath=file_object['filePath']
    return send_file(filePath, as_attachment=True)