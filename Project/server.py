from flask import Flask
from flask_pymongo import PyMongo
from flask import render_template, request, redirect, session
from cfg import config
from hashlib import sha256
from datetime import datetime
from utils import get_random_string


app = Flask(__name__)
app.config["MONGO_URI"] = config['mongo_uri']
mongo = PyMongo(app)

app.secret_key = b'riarhg3898%^'
@app.route('/')
def show_index():
	if not 'userToken' in session:
		session['error']='You must login to access this page'
		return redirect('/login')
	#validate user token
	token_document=mongo.db.user_tokens.find_one({
		'sessionHash' : session['userToken'],
		})

	if token_document is None:
		session.pop('userToken', None)
		session['error']='You must login again to access this page'
	return 'This is my secure homepage'

@app.route('/login')
def show_login():
	if 'userToken' in session:
		#validate user token from database
		pass
	signupSuccess =''
	if 'signupSuccess' in session:
		signupSuccess=session['signupSuccess']
		session.pop('signupSuccess', None)

	error=''
	if 'error' in session:
		error=session['error']
		session.pop('error', None)	
	return render_template('login.html', signupSuccess=signupSuccess, error=error)

@app.route('/check_login', methods=['POST'])
def check_login():
	
	try:
		password=request.form['password5']
	except KeyError:
		password=''

	try:
		email=request.form['email5']
	except KeyError:
		email=''    
	#check if email is blank
	if not len(email)>0 :
		session['error']='Email is required'
		return redirect('/login')
	
	#check if password is blank
	if not len(password)>0 :
		session['error']='Password is required'
		return redirect('/login')

	#find email in database
	user_document = mongo.db.users.find_one({"email" : email})
	if user_document is None:
	  #user doc with given email not found
	  session['error']='No account exists with this email address'
	  return redirect('/login')

	#verify that password hash matches with original
	password_hash = sha256(password.encode('utf-8')).hexdigest() 
	if user_document['password']!=password_hash:
	  session['error']='Password is wrong'
	  return redirect('/login')	
	
	#generate token and save it to session
	random_string=get_random_string()
	randomSessionHash = sha256(random_string.encode('utf-8')).hexdigest()
	token_object=mongo.db.user_tokens.insert_one({
		'userId' : user_document['_id'],
		'sessionHash' : randomSessionHash,
		'createdAt' : datetime.utcnow()
		})

	session['userToken']=randomSessionHash
	return redirect('/')

@app.route('/signup')
def show_signup():
	error=''
	if 'error' in session:
		error=session['error']
		session.pop('error', None)

	return render_template('signup.html', error=error)    

@app.route('/handle_signup', methods=['POST'])
def handle_signup():
	try:
		password=request.form['password']
	except KeyError:
		password=''

	try:
		email=request.form['email']
	except KeyError:
		email=''    
	

	#check if email is blank
	if not len(email)>0 :
		session['error']='Email is required'
		return redirect('/signup')

	#check if email is valid
	if not '@' in email or not '.' in email or ' ' in email :
		session['error']='Email is invalid'
		return redirect('/signup')

	#check if password is blank
	if not len(password)>0 :
		session['error']='Password is required'
		return redirect('/signup')

	#check if password is valid
	
	#Check if email already exists
	matching_user_count=mongo.db.users.count_documents({"email" : email})
	if matching_user_count>0 :
		session['error'] = 'Email already exists'
		return redirect('/signup')

	password = sha256(password.encode('utf-8')).hexdigest()	

	#Create user data base
	result=mongo.db.users.insert_one({
		'email': email,
		'password' : password,
		'name' : '',
		'lastLoginDate' : None,
		'createdAt' : datetime.utcnow(),
		'updatedAt' : datetime.utcnow()
		})
	#redirect to login page
	session['signupSuccess'] = 'Your user account is ready. You can login now'
	return redirect('/login')

@app.route('/logout')
def logout_user():
   session.pop('userToken', None)
   session['signupSuccess']='You are now logged out.' 
   return redirect('/login')

