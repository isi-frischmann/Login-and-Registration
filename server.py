from flask import (Flask, render_template, request, session, flash, redirect)
from mysqlconnection import connectToMySQL
from flask_bcrypt import Bcrypt

import re
import datetime as dt
from time import strftime 

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
NAME_REGEX = re.compile(r'^[a-zA-Z-]+$')
PW_REGEX = re.compile(r'[A-Z].*[0-9]|[0-9].*[A-Z]')

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = 'thisIsSecret'
mysql = connectToMySQL('logindb')

# print('all the users', mysql.query_db("SELECT * FROM user;"))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def check():
    fn = request.form['firstname']
    ln = request.form['lastname']
    em = request.form['email']
    pw = request.form['password']
    cf_password = request.form['cf_password']
    bd = request.form['birthdate']

    # print(request.form)

    # result = mysql.query_db(query, data)

    if len(fn) < 1:
        # print('------------------')
        flash('Name need to have more then two character', 'firstname')
        return redirect('/')
    elif not NAME_REGEX.match(fn) and NAME_REGEX.match(ln):
        # print('-----------------------')
        flash('Name can not contain any number', 'firstname')
        return redirect('/')

    if len(ln) < 1:
        # print('-----------------------')
        flash('Lastname can not be less then two character', 'lastname') 
        return redirect('/')
        
    if len(em) < 1:
        # print('-----------------------')
        flash('Email need to be a propper email address', 'email')
        return redirect('/')
    elif not  EMAIL_REGEX.match(em):
        # print('-----------------------')
        flash('Invalid Email Address!', 'email')
        return redirect('/')

    if len(pw) < 8:
        # print('-----------------------')
        flash('Password needs to have more then 8 characters', 'password')
        return redirect('/')
    if pw != cf_password:
        flash ('Confirmation password needs to match the Password', 'confirm_password')
        return redirect('/')
    elif not pw.isalpha() == False: #isalpha check for the presence of only alphabets
        flash('Password should contain atleast one number', 'password')
        return redirect('/')
    temp = pw.lower() #creat temp variable to change the password into lower capital
    if temp == pw: #check if the temp (all lower case) match the password - if yes there is no upper case contained
        flash('Password should contain atleast one capital letters', 'password')
        return redirect('/')

    #After all check statemens insert the method that password will be bcrypt.
    #Then insert the mySql Query

    pw_hash = bcrypt.generate_password_hash(request.form['password'])
    print(pw_hash)

    # print(request.form)
    query = "INSERT INTO user(first_name, last_name, email, password, cf_password, birthdate, created_at, updated_at) VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password_hash)s, %(cf_password)s, %(birthdate)s, NOW(), NOW());"
    data = {
        'first_name': request.form['firstname'],
        'last_name': request.form['lastname'],
        'email': request.form['email'],
        'password': pw_hash,
        'birthdate': request.form['birthdate']
    }
    session['first_name'] = request.form['firstname']
    mysql.query_db(query, data)
    return redirect('/added')

@app.route('/added')
def success():
    flash('Thanks for your registration, {}'.format(session['first_name']))
    return render_template('success.html')

@app.route('/login', methods=["POST"])
def login():
    data = { "email": request.form["email"] }
    query = "SELECT * FROM user WHERE email = %(email)s;"
    result = mysql.query_db(query, data)
    print("$" * 50)
    print(result)
    if result:
        if bcrypt.check_password_hash(result[0]['password'], request.form['password']):
            session['userid'] = result[0]['id']
    return redirect('/success')

@app.route('/success')
def correct_login():
    return render_template('logged_in.html')

if __name__ == '__main__':
    app.run(debug = True)