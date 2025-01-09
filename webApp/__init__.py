from flask import Flask, cli, Response, flash, render_template, request, redirect, url_for, request, jsonify, session, make_response, send_from_directory

from flask import Response

from werkzeug.utils import secure_filename
from datetime import *
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_mail import Mail, Message
from flask_bootstrap import Bootstrap
from flask_session import Session
# from flask_mysqldb import MySQL,MySQLdb


from flask_bcrypt import Bcrypt
import sys
from email.message import EmailMessage
import ssl
import smtplib
import csv
import pandas as pd
import numpy as np
import logging
import json


# new imports
import io
import time
import threading
import math
from threading import Lock
import queue
#sys.path.append('C:\cowplusonlinebeta.github.io\webApp\webApp')
import openconfig
from flask import request
from functools import wraps

import os

from datetime import date
from datetime import datetime
import shutil

max_size_mb = 1000
max_size_bytes = max_size_mb * 1024 * 1024

current_dir = os.path.dirname(os.path.abspath(__file__))
ALLOWED_EXTENSIONS = {'txt', 'csv'}
python_files_dir = os.path.join(current_dir, 'python_files')
upload_files_dir = os.path.join(current_dir, 'datafiles_csv')
config = openconfig.read_config()

# UPLOAD_FOLDER , SQLALCHEMY_DATABASE_URI

logging.basicConfig(level=logging.INFO)
app = Flask(__name__, template_folder='templates')
Bootstrap(app)
app.config["SECRET_KEY"] = "dJL1bnnSOCDi2Brtt04x"
app.config['UPLOAD_FOLDER'] = config['UPLOAD_FOLDER']
app.config['SQLALCHEMY_DATABASE_URI'] = config['SQLALCHEMY_DATABASE_URI']
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# progress bar

#app.config['SESSION_TYPE'] = 'redis'  # use Redis for storing sessions
#app.config['SESSION_REDIS'] = Redis(host='localhost', port=5000)
app.permanent_session_lifetime = timedelta(minutes=60)

#Session(app)

import random
import re
import inspect

def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

db = SQLAlchemy(app)
migrate = Migrate(app, db)
mail = Mail(app)
bcrypt = Bcrypt(app)
route_lock = Lock()

def debug(label, variable):
    print("\n>>> (DEBUG) " + label + " : " + str(variable) + "\n")
    return

class users(db.Model):
    _id = db.Column("id", db.Integer, primary_key=True)
    name = db.Column("name", db.String(100))
    email = db.Column("email", db.String(100))
    password = db.Column("password", db.String(100))
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    is_confirmed = db.Column(db.Boolean, nullable=False, default=False)
    confirmed_on = db.Column(db.DateTime, nullable=True)
    needs_refresh = db.Column(db.Boolean, nullable=False, default=True)

    def __init__(self, name, email, password, is_admin=False, is_confirmed=False, confirmed_on=None, needs_refresh=True):
        self.name = name
        self.email = email
        self.password = password
        self.is_admin = is_admin
        self.is_confirmed = is_confirmed
        self.confirmed_on = confirmed_on
        self.needs_refresh = needs_refresh

email_sender = "cowplusnoreply@gmail.com"
email_password = "rkjhjkvetassfwkx"

all_d_files = []
all_m_files = []

all_d_files_shared = []
all_m_files_shared = []

dataframe = []
# local path []
sys.path.append(python_files_dir)
import variables # type: ignore
import upload # type: ignore
import data_merger # type: ignore

# -- routes -- #

def currentUserFolder():
    return os.path.join(config["UPLOAD_FOLDER"], session['user'])
def currentTempFolder():
    return os.path.join(config["UPLOAD_FOLDER"], session['user'], "temp")
def enable_refresh():
    user = session["user"]
    found_user = users.query.filter_by(name=user).first()
    found_user.needs_refresh = True
    db.session.commit()
    return

def enable_refresh_for_all():
    found_user = users.query.all()
    for user in found_user:
        user.needs_refresh = True
    db.session.commit()
    return

def log(action):
    ip_address = request.remote_addr  # Get client's IP address
    logging.info(f"\n\n[FLASK] >>> action: {action} // IP: {ip_address}\n")
    return

def log_action(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip_address = request.remote_addr
        logging.info(f"\n\n[FLASK] >>> action: {request.url_rule}, // IP: {ip_address}\n")
        return f(*args, **kwargs)
    return decorated_function

def sendverification(code):
   em = EmailMessage()
   email_receiver = str(session["email"])
   subject = "Email verification code"
   body = "Your verification code is: " + str(code)
   em['From'] = email_sender
   em['To'] = email_receiver
   em['Subject'] = subject
   em.set_content(body)
   context = ssl.create_default_context()

   with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
       smtp.login(email_sender, email_password)
       smtp.sendmail(email_sender, email_receiver, em.as_string())
   return "sent"

def create_citations():
    return

# app routes

@app.route("/testupload", methods=['GET','POST'])
def testupload():

    return render_template("testupload.html")

@app.route('/get-username')
def get_username():
    print("\n\n\n\n\n\ngetusername")
    username = session['user']
    return jsonify(username=username)

@app.route('/receive-username', methods=['POST'])
def receive_username():
    print("\n\n\n\n\n\nrecieveusername")
    data = request.json
    username = data['username']
    response_from_variables = variables.process_username(username)
    
    return jsonify({"status": "success", "responseFromVariables": response_from_variables})

@app.cli.command("init-db")
def init_db():
    db.create_all()
    print("Database initialized.")

@app.cli.command('listusers')
def list_users():
    all_users = users.query.all()
    for user in all_users:
        print(f'ID: {user._id}, Name: {user.name}, Email: {user.email}, Password (hashed): {user.password}')

@app.cli.command("createadmin")
def create_admin():
    nm = input("Enter username: ")
    em = input("Enter email address: ")
    password = input("Enter password: ")
    try:
        user = users(
            name=nm,
            email=em,
            password=bcrypt.generate_password_hash(password).decode('utf-8'),
            is_admin=True,
            is_confirmed=True,
            confirmed_on=datetime.now(),
            needs_refresh=True,
        )
        db.session.add(user)
        db.session.commit()
        print(f"Admin with name {nm} and email {em} created successfully!")
    except Exception as e:
        print("Couldn't create admin user.")
        print(e)
'''
@app.cli.command("resetdatabase")
def delall():
    print("Are you sure you want to delete all users from the database? This action is irreversible.\nType \"CONFIRM\" to reset the database.")
    confirm = input("> ")
    if confirm == "CONFIRM":
        found_user = users.query.all()
        for user in found_user:
            db.session.delete(user)
            db.session.commit()
        print("All users wiped.")
    else:
        print("Wipe aborted.")
'''
@app.route("/")
def home():
    return redirect("/index.html")

def logip():
    ip_address = request.remote_addr
    logging.debug(f"/reset request from {ip_address},", session["user"])
    return

# resets the whole user database
'''@app.route("/reset", methods=['POST'])
def reset():
    if request.method == 'POST':
        if "user" in session and "is_admin" in session and session["is_admin"]:
            found_user = users.query.all()
            for user in found_user:
                db.session.delete(user)
                db.session.commit()
            flash("All users wiped.")
        else:
            flash("You are not authorized to perform this action.")
            return redirect(url_for('login'))  # redirect unauthorized users
    return redirect("/panel")'''

@app.route('/delete_user/<username>', methods=['POST', 'GET'])
def delete_user(username):
    # find the user by username
    #if request.method == 'POST':
    if "user" in session and "is_admin" in session and session["is_admin"]:
        user = users.query.filter_by(name=username).first()
        if user:
            db.session.delete(user)
            db.session.commit()
            flash("User deleted successfully.")
        else:
            flash("User not found.")
    else:
        flash("You are not authorized to perform this action.")
        return redirect(url_for('login'))  # redirect unauthorized users
    return redirect("/panel")

@app.route('/login_user/<username>', methods=['POST', 'GET'])
def login_user(username):
    # to be used only for testing purposes
    if "user" in session and "is_admin" in session and session["is_admin"]:
        found_user = users.query.filter_by(name=username).first()

        if found_user:
            flash("logged in successfully")
            session.clear()
            session["user"] = username
            session["email"] = found_user.email
            session["is_admin"] = found_user.is_admin
            session["verified"] = found_user.is_confirmed
        else:
            flash("no user found")
    return redirect("/user")

@app.route('/make_admin/<username>', methods=['POST', 'GET'])
def make_admin(username):
    if "user" in session and "is_admin" in session and session["is_admin"]:
        user = users.query.filter_by(name=username).first()
        if user:
            user.is_admin = True
            db.session.commit()
            flash("User changed to admin successfully.")
        else:
            flash("User not found.")
    else:
        flash("You are not authorized to perform this action.")
        return redirect(url_for('login'))  # redirect unauthorized users
    return redirect("/panel")

@app.route('/remove_admin/<username>', methods=['POST', 'GET'])
def remove_admin(username):
    if "user" in session and "is_admin" in session and session["is_admin"]:
        user = users.query.filter_by(name=username).first()
        if user:
            user.is_admin = False
            db.session.commit()
            flash("Removed admin successfully.")
        else:
            flash("User not found.")
    else:
        flash("You are not authorized to perform this action.")
        return redirect(url_for('login'))  # redirect unauthorized users
    return redirect("/panel")

 

@app.route('/upload.html', methods=['GET', 'POST'])
def goto_upload():
    if "user" in session:
        if session["verified"] == True:
            print(session["verified"])
            return render_template("upload.html")
        else:
            return redirect(url_for("verify"))
    else:
        flash("You must be logged in to access this page.")
        return redirect("/login")

def upload_file():
    if "user" in session:
        if session["verified"] == True:
            print(session["verified"])
            if request.method == 'POST':
                # check if the post request has the file part
                if 'file' not in request.files:
                    flash('No file part')
                    return redirect(request.url)
                file = request.files['file']
                # If the user does not select a file, the browser submits an
                # empty file without a filename.
                if file.filename == '':
                    flash('No selected file')
                    return redirect(request.url)
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    debug("legacy upload", "called")
                    return redirect(url_for('shared_download_file', name=filename))
            return render_template("upload.html")
        else:
            return redirect(url_for("verify"))
    else:
        flash("You must be logged in to access this page.")
        return redirect("/login")
    
@app.route("/index.html")
def goto_index():
    return render_template("index.html")

@app.route("/guides.html")
def goto_guide():
    return render_template("guides.html")

@app.route("/privacy_policy.html")
def goto_privacy_policy():
    return render_template("privacy_policy.html")

@app.route("/terms_of_service.html")
def goto_tos():
    return render_template("terms_of_service.html")

@app.route("/dataUnlimVar.html", methods=["POST", "GET"])
def goto_dataUnlimVar():
    if "user" in session:
        session["yearMin"] = 1000 ###
        session["yearMax"] = 3000
        if not os.path.exists(currentTempFolder()):
            os.mkdir(currentTempFolder())
        user = session["user"]
        found_user = users.query.filter_by(name=user).first()
        if found_user.needs_refresh == True:
            print("needs refresh")
        print("user in session")
        directory_to_check = config["UPLOAD_FOLDER"] + "/" + session["user"]
        if not os.path.isdir(directory_to_check):
            os.makedirs(directory_to_check)
    else:
        print("no user in session")
        flash("You must be logged in to access this page.")
        return redirect(url_for("login"))
    if request.method == 'POST':
        return render_template("dataUnlimVar.html")
    else:
        return render_template("dataUnlimVar.html")
    
@app.route("/download.html")
def goto_download():
    return render_template("download.html")

@log_action
@app.route("/panel", methods=["POST", "GET"])
def view():
    if "user" in session:
        ip_address = request.remote_addr
        logging.info(f"/panel request from {ip_address}")
        if "is_admin" in session and session["is_admin"]:
            return render_template("view.html", values=users.query.all())
    return '''<p>Access denied</p>''' 

@app.route("/enable_refresh_for_all", methods=['POST', 'GET'])
def enable_refresh_for_all_page():
    if "user" in session:
        ip_address = request.remote_addr
        logging.info(f"/panel request from {ip_address}")
        if "is_admin" in session and session["is_admin"]:
            enable_refresh_for_all()
            return "enabled refresh for all"
    return '''<p>Access denied</p>''' 

@app.route('/verifyFunction/', methods=['POST', 'GET'])  
def verifyFunction():
    global all_m_files, all_d_files
    verified = False
    # Get the list of files from webpage
    files = request.files.getlist("file")
    print(files)
    username = session["user"]
    directory_to_check = os.path.join(config["UPLOAD_FOLDER"], username)
    if not os.path.isdir(directory_to_check):
        os.makedirs(directory_to_check)

    # Iterate for each file in the files List, and Save them
    if files[0].filename != "":
        for file in files:
            first_line = file.readline().decode().strip()
            debug("first_line", first_line)
            file.seek(0)
        session["m_files"], session["d_files"], session["g_files"], session["b_files"] = upload.verify_files(first_line, file)
        if(len(session["b_files"]) == 0):
            verified = True
        
    if(len(files) == 0):
        verified = False
    response = {
        "message": "data processing successful",
        "status": 200,
        "good_files": session["g_files"],
        "bad_files": session["b_files"],
        "verification": verified
    }
    session.pop("g_files", None)
    session.pop("b_files", None)
    
    return response

def get_directory_size(directory):
    total_size = 0
    for dirpath, dirnames, filenames in os.walk(directory):
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            if os.path.isfile(file_path):  # Ensure it's a file
                total_size += os.path.getsize(file_path)
    return total_size

@app.route('/uploadFunction/', methods = ['POST', 'GET'])
def uploadFunction():
    global max_size_bytes
    debug("upload", "called")
    for m in session["m_files"]:
        all_m_files.append(m)
    for d in session["d_files"]:
        all_d_files.append(d)
    files = request.files.getlist("file")
    citation = request.form['citation']
    print("dbg.citation: " + citation)
    username = session["user"]
    citations = load_citations_from_json(os.path.join(config["BASE"], "citations.json"))
    directory_to_check = os.path.join(config["UPLOAD_FOLDER"], username)
    current_size = get_directory_size(directory_to_check)
    if not os.path.isdir(directory_to_check):
        os.makedirs(directory_to_check)
    debug("dirsize", current_size)
    base_file = ""
    new_files_size = 0
    for file in files:
        base_file = file.filename.split(".")[0]
        debug("base_file", base_file)
        
        # Move the file pointer to the start of the file
        file.stream.seek(0, os.SEEK_END)
        file_size = file.stream.tell()  # Get the current position in the stream, which is the size
        file.stream.seek(0)  # Reset the file pointer to the start of the file
        new_files_size += file_size
        print(f"File: {file.filename}, Size: {file_size} bytes")
    
    
    debug("new_files_size", new_files_size)

    if new_files_size + current_size < max_size_bytes:
        os.chdir(os.path.join(config["UPLOAD_FOLDER"], username))
        
        for file in files:
            file.save(file.filename)
            print("saved")
        session["m_files"] = []
        session["d_files"] = []
        session["g_files"] = []
        session["b_files"] = []
        citations[base_file] = citation
        save_citations_to_json(citations, os.path.join(config["BASE"], "citations.json"))

        user = session["user"]
        found_user = users.query.filter_by(name=user).first()
        found_user.needs_refresh = True
        db.session.commit()
    else:
        print("Storage limit reached")
        flash("Storage limit of 3GB reached. Remove existing files or upgrade to upload.")
    
    return redirect('/upload.html')

@app.route('/verifyFunctionShared/', methods=['POST', 'GET'])  
def verifyFunctionShared():
    verified = False
    # Get the list of files from webpage
    files_shared = request.files.getlist("file")
    debug("files_shared", files_shared)
    os.chdir(app.config['UPLOAD_FOLDER'].replace("datafiles_csv", "datasets_shared"))
    # Iterate for each file in the files List, and Save them    
    debug("files_shared", files_shared)
    if files_shared[0].filename != "":
        for file in files_shared:
            first_line = file.readline().decode().strip()
            debug("first_line", first_line)
            file.seek(0)
        session["m_files_shared"], session["d_files_shared"], session["g_files_shared"], session["b_files_shared"] = upload.verify_files(first_line, file)
        if(len(session["b_files_shared"]) == 0):
            verified = True
    if(len(files_shared) == 0):
        verified = False

    response = {
        "message": "data processing successful",
        "status": 200,
        "good_files": session["g_files_shared"],
        "bad_files": session["b_files_shared"],
        "verification": verified
    }
    session.pop("g_files", None)
    session.pop("b_files", None)
    return response

@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        log("login")
        session.permanent = True
        user = request.form["nm"]
        pwd = request.form["pwd"]

        found_user = users.query.filter_by(name=user).first()
        found_email = users.query.filter_by(email=user).first()

        if found_user:
            if bcrypt.check_password_hash(found_user.password, pwd):
                session["user"] = user
                session["email"] = found_user.email
                session["is_admin"] = found_user.is_admin
                session["verified"] = found_user.is_confirmed
                session["needs_refresh"] = found_user.needs_refresh
            else:
                flash("Password incorrect.")
                return redirect(url_for("login"))
        elif found_email:
            if bcrypt.check_password_hash(found_email.password, pwd):
                session["user"] = found_email.name
                session["email"] = user
                session["is_admin"] = found_email.is_admin
                session["verified"] = found_email.is_confirmed
                session["needs_refresh"] = found_user.needs_refresh
            else:
                flash("Password incorrect.")
                return redirect(url_for("login"))

        else:
            flash("User does not exist")
            return redirect(url_for("login"))

        return redirect(url_for("user"))
    else:
        if "user" in session:
            flash("Already logged in!")
            return redirect(url_for("user"))
        return render_template("login.html")


def remove_items(test_list, item):

    # using list comprehension to perform the task
    res = [i for i in test_list if i != item]
    return res

@app.route("/signup.html", methods=["POST", "GET"])
def signup():
    if request.method == "POST":
        log("signup")
        session.permanent = True
        user = request.form["nm"].lower()
        em = request.form["em"].lower()
        cem = request.form["cem"].lower()
        pwd = request.form['pwd']

        if em != cem:
            flash("Emails do not match.")
            return render_template("signup.html")

        if len(user) > 15 or len(user) < 5 or not user.isalnum():
            flash("Username must be between 5-15 characters and must contain only lowercase numbers and letters.")
            return render_template("signup.html")

        if len(pwd) < 8 or not re.search("[a-zA-Z]", pwd) or not re.search("[0-9]", pwd):
            flash("Password must be at least 8 characters long and include both letters and numbers.")
            return render_template("signup.html")

        found_user = users.query.filter_by(name=user).first()
        found_email = users.query.filter_by(email=em).first()

        if found_user:
            flash("Username already in use.")
            return render_template("signup.html")
        if found_email:
            flash("Email already in use.")
            return render_template("signup.html")
        
        if user and em and pwd:
            if re.match(r"[^@]+@[^@]+\.[^@]+", em):
                try:
                    session["user"] = user
                    session["email"] = em
                    session["verified"] = False
                    
                    directory_path = os.path.join(config["UPLOAD_FOLDER"], session["user"])
                    if not os.path.exists(directory_path):
                        os.mkdir(directory_path)
                    else:
                        flash("There was an error with the server filesystem. Please try a different username.")
                        session.clear()
                        return render_template("signup.html")
                    
                    hashed_pwd = bcrypt.generate_password_hash(pwd).decode('utf-8')
                    usr = users(name=user, email=em, password=hashed_pwd)  # assuming the 'users' model takes these parameters
                    db.session.add(usr)
                    db.session.commit()

                    if not os.path.exists(currentTempFolder()):
                        os.mkdir(currentTempFolder())

                    flash("User created")
                    
                    return redirect(url_for("verify"))
                except Exception as e:
                    db.session.rollback()
                    flash("An error occurred during registration. Please try again.")
                    debug("signup error", str(e))  # Log the error for further analysis
                    return render_template("signup.html")
            else:
                flash("Enter a valid email")
                return render_template("signup.html")
        else:
            flash("Please fill out all fields")
            return render_template("signup.html")
    else:
        if "user" in session:
            flash("Already logged in!")
            return redirect(url_for("user"))
        return render_template("signup.html")
    
@app.route("/verify", methods=["POST", "GET"])
def verify():
    if "user" in session:
        if session["verified"] == False:
            if request.method == "POST":
                log("verify")
                userinput = request.form["code"]
                if str(userinput) == str(session["code"]):
                    flash("Verification successful!")
                    user = users.query.filter_by(name=session["user"]).first()
                    user.is_confirmed = True
                    user.confirmed_on = datetime.now()
                    db.session.commit()
                    session["verified"] = True
                    return redirect(url_for("goto_dataUnlimVar"))
                else:
                    flash("Incorrect code. (Refresh this page for a new code)")
                    print("form:", userinput)
                    print("code:", session["code"])
                    return render_template("verify.html")
            else:
                log("sendcode")
                # send email with code  
                code = random.randint(100000, 999999)
                session["code"] = code
                sendverification(code)
                print(session["code"])
                return render_template("verify.html")
    return redirect(url_for("login"))

from flask import Flask, render_template, request, redirect, url_for, send_file
import csv
from io import StringIO, BytesIO

user_files = {}  # Dictionary to store user metadata and their corresponding file names
def create_chicago_citation(metadata):
    """
    Create a Chicago-style citation from metadata.
    
    Args:
        metadata (dict): A dictionary containing citation metadata.
            - author_name (str): The name of the author.
            - article_title (str): The title of the article.
            - title (str): The title of the journal or book.
            - inclusive_pages (str): The inclusive page numbers of the article.
            - volume (str): The volume number of the journal.
            - issue (str): The issue number of the journal.
            - year (str): The year of publication.
            - month (str): The month of publication.
    
    Returns:
        str: A formatted Chicago-style citation.
    """
    author_name = metadata.get('author_name', '')
    article_title = metadata.get('article_title', '')
    title = metadata.get('title', '')
    inclusive_pages = metadata.get('inclusive_pages', '')
    volume = metadata.get('volume', '')
    issue = metadata.get('issue', '')
    year = metadata.get('year', '')
    month = metadata.get('month', '')

    citation = f"{author_name}. \"{article_title}.\" {title} {volume}, no. {issue} ({month} {year}): {inclusive_pages}."
    
    return citation

def append_to_file(filename, citation, file_path):
    filename = filename.split(".")[0]
    to_append = "\n" + filename + "=" + citation# Add a newline character for formatting
    try:
        with open(file_path, 'a') as file:
            file.write(to_append)
        print(f"Appended to file: {file_path}")
    except Exception as e:
        print(f"An error occurred while appending to the file: {e}")
###
def load_citations_from_json(file_path):
    """Load citations from a JSON file."""
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            return json.load(f)
    else:
        return {}

def save_citations_to_json(citations, file_path):
    """Save citations to a JSON file."""
    with open(file_path, 'w') as f:
        json.dump(citations, f, indent=4)
# ..
'''
def remove_items(test_list, item):
    for m in m_files_shared:
        all_m_files_shared.append(m)
    for d in d_files_shared:
        all_d_files_shared.append(d)
    # using list comprehension to perform the task
    res = [i for i in test_list if i != item]
    return res
'''
@app.route("/shared.html", methods=["POST", "GET"])
def importpage():
    if "user" in session:
        if session["verified"] == True:
            if not os.path.exists(currentTempFolder()):
                os.mkdir(currentTempFolder())
            IMPORT_FOLDER = app.config['UPLOAD_FOLDER'].replace("datafiles_csv", "datasets_shared")
            global user_files
            global all_m_files_shared, all_d_files_shared
            print("dbg: IMPORT_FOLDER = " + IMPORT_FOLDER)
            if request.method == 'POST':
                citations = load_citations_from_json(os.path.join(config["BASE"], "citations.json"))
                citation= request.form['citation']
                for m in session["m_files_shared"]:
                    all_m_files_shared.append(m)
                for d in session["d_files_shared"]:
                    all_d_files_shared.append(d)
                if 'file' in request.files:
                    files = request.files.getlist('file')
                    for file in files:
                        if file.filename == '':
                            continue
                        ###
                        filename = str(session['user'] + "_" + secure_filename(file.filename))
                        file.save(os.path.join(IMPORT_FOLDER, filename))
                        ###
                        # Read the content of the file and store it
                        stream = StringIO(file.stream.read().decode("UTF8"), newline=None)
                        csv_input = csv.reader(stream)
                        file_data = list(csv_input)
                        # to change; have individuals put manual citations.
                        citations[filename.split(".")[0]] = citation

                        save_citations_to_json(citations, os.path.join(config["BASE"], "citations.json"))

            session["m_files_shared"] = []
            session["d_files_shared"] = []
            session["g_files_shared"] = []
            session["b_files_shared"] = [] 
            files = os.listdir(IMPORT_FOLDER)
            file_contents = [{'filename': f} for f in files]
            return render_template("shared.html", file_contents=file_contents, session_user = session['user'])
        else:
            return redirect(url_for("verify"))
    else:
        flash("You must be logged in to access this page.")
        return redirect("/login")

def construct_preview(file_path):
    print("dbg.file_path.preview = " + file_path)
    # Check if file exists
    if not os.path.exists(file_path):
        return "File not found", 404
    
    # Read the CSV file
    try:
        df = pd.read_csv(file_path, nrows=100)
    except Exception as e:
        return f"An error occurred while reading the CSV file: {e}", 500
    
    # Convert DataFrame to HTML
    html_table = df.to_html(classes='table table-striped', index=False)

    html = f"""
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
        <link rel="stylesheet" href="../static/css/bootstrap.min.css">
        <link rel="stylesheet" href="../static/SlickGrid-2.4.44/slick.grid.css" type="text/css"/>
        <link rel="stylesheet" href="../static/SlickGrid-2.4.44/examples/examples.css" type="text/css"/>
        <title>CSV Preview</title>
      </head>
      <body>
        <div class="container" style="padding-left:20px; width=100%; height = 100vh">
          <h4 class="mt-5">Preview of {file_path.split("/")[-1]} (first 100 rows)</h4>
          <div class="slickgrid_viewport" style="width=50%; height:80vh; overflow:scroll;">
            {html_table}
          </div>
        </div>
      </body>
    </html>
    """

    return html

@app.route("/uploaded_preview", methods=["POST", "GET"])
def uploaded_preview():
    if request.method == "POST":
        filename = request.form['filename']
    # Construct the full file path
    file_path = config["UPLOAD_FOLDER"] + "/" + session["user"] + "/" + filename
    
    return construct_preview(file_path)

@app.route("/shared_preview", methods=["POST", "GET"])
def shared_preview():
    if request.method == "POST":
        filename = request.form['filename']
    # Construct the full file path
    file_path = config["BASE"] + "/datasets_shared/" + filename
    
    return construct_preview(file_path)


def copy_file_to_folder(file_path, destination_folder):
    """
    Copy a file to the specified folder.
    
    Args:
        file_path (str): The full path to the file to be copied.
        destination_folder (str): The folder where the file should be copied.
    
    Returns:
        str: The path to the copied file, or an error message.
    """
    try:
        # Ensure the destination folder exists
        if not os.path.exists(destination_folder):
            os.makedirs(destination_folder)
        
        # Get the filename from the file path
        filename = os.path.basename(file_path)
        
        # Construct the full destination path
        destination_path = os.path.join(destination_folder, filename)
        
        # Copy the file
        shutil.copy(file_path, destination_path)
        
        return f"File copied to {destination_path}"
    except Exception as e:
        return f"An error occurred: {e}"

@app.route("/import", methods=["POST"])
def import_file():
    print("dbg: import req sent")
    if 'user' in session:  
        filename = request.form['filename']
        file_path = config["BASE"] + "/datasets_shared/" + filename
        destination_folder = config["UPLOAD_FOLDER"] + "/" + session['user']
        print("dbg.file_path = " + file_path)
        print("dbg.destination_folder = " + destination_folder)
        try:
            # Ensure the destination folder exists
            if not os.path.exists(destination_folder):
                os.makedirs(destination_folder)
            debug("importing", filename)
            copy_file_to_folder(file_path, destination_folder)
            flash(f"Successfully imported {filename}")
            enable_refresh()
            return redirect(url_for('importpage'))
        except Exception as e:
            return f"An error occurred: {e}"
        
    else:
        flash("You must be logged in to import data.")
        return redirect(url_for('login'))
    
def delete_file(file_path):
    try:
        # Check if file exists
        if os.path.exists(file_path):
            os.remove(file_path)
        else:
            return f"File not found", 404
    except Exception as e:
        return str(e), 500

@app.route("/shared_delete", methods=["POST"])
def shared_delete_file():
    global file_contents, user_files
    filename_to_delete = request.form['filename']
    base_name = filename_to_delete.split(".")[0]
    directory = config["BASE"] + "/datasets_shared"
    if filename_to_delete.split("_")[0] != session["user"]:
        debug("filename_to_delete.split('_')[0]", filename_to_delete.split("_")[0])
        flash(f"Permission denied. Please reach out if you believe this is a mistake.")
        return redirect(url_for('importpage'))
    else:
    # Construct the full file path
        file_path = os.path.join(directory, filename_to_delete)
        
        try:
        # Check if file exists
            if os.path.exists(file_path):
                os.remove(file_path)
                flash(f"File '{filename_to_delete}' deleted successfully")
            else:
                flash(f"File '{filename_to_delete}' not found")
            
            # Load current citations
            citations = load_citations_from_json(os.path.join(config["BASE"], "citations.json"))
            debug("citations before deletion", citations)
            # Remove the citation associated with the filename
            if base_name in citations:
                del citations[base_name]
                # Save the updated citations back to the JSON file
                save_citations_to_json(citations, os.path.join(config["BASE"], "citations.json"))
                flash(f"Citation for '{filename_to_delete}' deleted successfully")
            else:
                flash(f"Citation for '{filename_to_delete}' not found")

            return redirect(url_for('importpage'))

        except Exception as e:
            return str(e), 500

@app.route("/uploaded_delete", methods=["POST"])
def uploaded_delete_file():
    global file_contents, user_files
    filename_to_delete = request.form['filename']
    citations = load_citations_from_json(os.path.join(config["BASE"], "citations.json"))
    base_name = filename_to_delete.split(".")[0]
    directory = os.path.join(config["UPLOAD_FOLDER"], session["user"])
    
    # Construct the full file path
    file_path = os.path.join(directory, filename_to_delete)
    
    try:
        # Check if file exists
        if os.path.exists(file_path):
            os.remove(file_path)
            flash(f"File '{filename_to_delete}' deleted successfully")
            
        else:
            flash(f"File '{filename_to_delete}' not found")
        
        if base_name in citations:
            del citations[base_name]
            # Save the updated citations back to the JSON file
            save_citations_to_json(citations, os.path.join(config["BASE"], "citations.json"))
            enable_refresh()
            flash(f"Citation for '{filename_to_delete}' deleted successfully")
        else:
            flash(f"Citation for '{filename_to_delete}' not found")
        return redirect(url_for('user'))
    except Exception as e:
        return str(e), 500

@app.route("/shared_download", methods=["POST"])
def shared_download_file():
    filename_to_download = request.form['filename']
    print("dbg.filename = " + filename_to_download)
    # Define the directory where the files are located
    directory = config["BASE"] + "/datasets_shared"
    try:
        return send_from_directory(directory, filename_to_download, as_attachment=True)
    except FileNotFoundError:
        return "File not found", 404
    return redirect(url_for('importpage'))

@app.route("/uploaded_download", methods=["POST"])
def uploaded_download_file():
    filename_to_download = request.form['filename']
    print("dbg.filename = " + filename_to_download)
    # Define the directory where the files are located
    directory = os.path.join(config["UPLOAD_FOLDER"], session["user"])
    try:
        return send_from_directory(directory, filename_to_download, as_attachment=True)
    except FileNotFoundError:
        return "File not found", 404
    return redirect(url_for('importpage'))

def convert_size(size_bytes):
    if size_bytes == 0:
        return "0B"
    size_name = ("B", "KB", "MB", "GB", "TB", "PB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p)
    return f"{s} {size_name[i]}"

@app.route("/user", methods=["POST", "GET"])
def user():
    global max_size_bytes
    email = None
    if "user" in session:
        if session["verified"] == False:
            flash("Please verify your email.")
        user = session["user"]
        found_user = users.query.filter_by(name=user).first()
        if request.method == "POST":
            email = request.form["email"]
            session["verified"] = False
            found_user.is_confirmed = False
            session["email"] = email
            found_user.email = email
            db.session.commit()
            flash("Email saved!")
            return redirect(url_for("verify"))
        else:
            if "email" in session:
                email = session["email"]
        username = found_user.name
        flash("Logged in as " + username)

        filesfolder = config["UPLOAD_FOLDER"] + "/" + username
        print("dbg.filesfolder: " + filesfolder)
        files = os.listdir(filesfolder)

        csv_files = [file for file in files if file.endswith('.csv')]
        debug("files", files)
        file_contents = [{'filename': f} for f in csv_files]

        directory_to_check = os.path.join(config["UPLOAD_FOLDER"], username)
        current_size_bytes = get_directory_size(directory_to_check)
        percent_full = round((current_size_bytes / max_size_bytes) * 100, 2)

        debug("currentsize", current_size_bytes)
        debug("max_size_bytes", max_size_bytes)
        debug("percent_full", percent_full)
        current_size = convert_size(current_size_bytes)

        return render_template("user.html", email=email, file_contents=file_contents, current_size=current_size, percent_full=percent_full)
    else:
        return redirect(url_for("login"))

@app.route("/logout")
def logout():
    log("logout")
    session.clear()
    flash("Logged out successfully.")
    return redirect(url_for("login"))

# gets variables for the variable table
def getVarJSONs():
    user = session["user"]
    found_user = users.query.filter_by(name=user).first()
    needs_refresh = found_user.needs_refresh
    if "user" in session:
        if needs_refresh:
            debug("needs refresh", "true")
            filenames = [
                "a_var_id.json",
                "m_var_id.json",
                "a_var_name.json",
                "m_var_name.json",
                "a_var_descrip.json",
                "m_var_descrip.json",
                "a_var_dataset.json",
                "m_var_dataset.json"
            ]
            for filename in filenames:
                if not os.path.exists(os.path.join(config["UPLOAD_FOLDER"], session['user'], "temp", filename)):
                    with open(os.path.join(config["UPLOAD_FOLDER"], session['user'], "temp", filename), 'w') as json_file:
                        json.dump({}, json_file, indent=4)
                    print(f"Created and wrote to {filename}")
                else:
                    print(f"{filename} already exists")

            a_var_id_json, m_var_id_json = variables.createVarGeneric(session["user"], "IDs")
            a_var_name_json, m_var_name_json = variables.createVarGeneric(session["user"], "Var")
            a_var_descrip_json, m_var_descrip_json = variables.createVarGeneric(session["user"], "Descrip")
            a_var_dataset_json, m_var_dataset_json = variables.createVarGeneric(session["user"], "Dataset")

            json_data_and_filenames = [
                (a_var_id_json, "a_var_id.json"),
                (m_var_id_json, "m_var_id.json"),
                (a_var_name_json, "a_var_name.json"),
                (m_var_name_json, "m_var_name.json"),
                (a_var_descrip_json, "a_var_descrip.json"),
                (m_var_descrip_json, "m_var_descrip.json"),
                (a_var_dataset_json, "a_var_dataset.json"),
                (m_var_dataset_json, "m_var_dataset.json")
            ]

            for json_data, filename in json_data_and_filenames:
                try:
                    # write JSON data to a file
                    with open(os.path.join(config["UPLOAD_FOLDER"], session['user'], "temp", filename), 'w') as json_file:
                        json.dump(json_data, json_file, indent=4)
                        debug("Exported data to", filename)
                except Exception as e:
                    debug("Failed to write", filename)

                found_user.needs_refresh = False
                db.session.commit()
        else: 
            pass
    else:
        # deprecated
        pass
    '''
    if "user" in session:
        session["a_var_id_json"], session["m_var_id_json"] = variables.createVarIDs_JS(session["user"])
        session["a_var_name_json"], session["m_var_name_json"] = variables.createVar_JS(session["user"])
        session["a_var_descrip_json"], session["m_var_descrip_json"] = variables.createVarDescrip_JS(session["user"])
        session["a_var_dataset_json"], session["m_var_dataset_json"] = variables.createVarDataset_JS(session["user"])
    else:
        session["a_var_id_json"], session["m_var_id_json"] = variables.createVarIDs_JS("test_profile")
        session["a_var_name_json"], session["m_var_name_json"] = variables.createVar_JS("test_profile")
        session["a_var_descrip_json"], session["m_var_descrip_json"] = variables.createVarDescrip_JS("test_profile")
        session["a_var_dataset_json"], session["m_var_dataset_json"] = variables.createVarDataset_JS("test_profile")'''

#gets variables for the first variable table
@app.route('/firstStepVarJSON/', methods=['POST', "GET"])
def firstStepVarJSON():
    getVarJSONs() 
    filenames = {
        "var_id_json": "a_var_id.json",
        "var_name_json": "a_var_name.json",
        "var_descrip_json": "a_var_descrip.json",
        "var_dataset_json": "a_var_dataset.json"
    }
    var_id_json = None
    var_name_json = None
    var_descrip_json = None
    var_dataset_json = None

    try:
        with open(os.path.join(currentTempFolder(), filenames["var_id_json"]), 'r') as file:
            var_id_json = json.load(file)
        print("Loaded var_id_json successfully.")

        with open(os.path.join(currentTempFolder(), filenames["var_name_json"]), 'r') as file:
            var_name_json = json.load(file)
        print("Loaded var_name_json successfully.")

        with open(os.path.join(currentTempFolder(), filenames["var_descrip_json"]), 'r') as file:
            var_descrip_json = json.load(file)
        print("Loaded var_descrip_json successfully.")

        with open(os.path.join(currentTempFolder(), filenames["var_dataset_json"]), 'r') as file:
            var_dataset_json = json.load(file)
        print("Loaded var_dataset_json successfully.")
    except FileNotFoundError as e:
        print(f"File not found: {e}")
        enable_refresh()
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
        enable_refresh()
    except Exception as e:
        print(f"An error occurred: {e}")
        enable_refresh()

    response = {
        "message": "vars",
        "status": 200,
        "name_json": var_name_json,
        "descrip_json": var_descrip_json,
        "var_id_json": var_id_json,
        "dataset_json": var_dataset_json
    }
    return response

#gets variables for the second variable table (after user merges dyadic data and chooses to add monadic data)
@app.route('/secondStepVarJSON/', methods=['POST', "GET"])
def secondStepVarJSON():
    filenames = {
        "var_id_json": "m_var_id.json",
        "var_name_json": "m_var_name.json",
        "var_descrip_json": "m_var_descrip.json",
        "var_dataset_json": "m_var_dataset.json"
    }
    var_id_json = None
    var_name_json = None
    var_descrip_json = None
    var_dataset_json = None
    try:
        with open(os.path.join(currentTempFolder(), filenames["var_id_json"]), 'r') as file:
            var_id_json = json.load(file)
        print("Loaded var_id_json successfully.")

        with open(os.path.join(currentTempFolder(), filenames["var_name_json"]), 'r') as file:
            var_name_json = json.load(file)
        print("Loaded var_name_json successfully.")

        with open(os.path.join(currentTempFolder(), filenames["var_descrip_json"]), 'r') as file:
            var_descrip_json = json.load(file)
        print("Loaded var_descrip_json successfully.")

        with open(os.path.join(currentTempFolder(), filenames["var_dataset_json"]), 'r') as file:
            var_dataset_json = json.load(file)
        print("Loaded var_dataset_json successfully.")
    except FileNotFoundError as e:
        print(f"File not found: {e}")
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")
    response = {
        "message": "vars",
        "status": 200,
        "name_json": var_name_json,
        "descrip_json": var_descrip_json,
        "var_id_json": var_id_json,
        "dataset_json": var_dataset_json
    }
    return response
'''
# variableChooser()
@app.route('/variableChooser', methods=['POST'])
def processvc():
    ###
    global vc
    data = request.get_json()
    vc = data['array']
    print(vc)
    ###
    data = request.get_json()
    session["vc"] = data['array']
    debug("session on vc", session)
    debug("sessionvc", session["vc"])
    return 'okay'
'''
'''# datasetChooser()
@app.route('/datasetChooser', methods=['POST'])
def processdc():
    ###
    global dc
    data = request.get_json()
    dc = data['array']
    ###
    data = request.get_json()
    session["dc"] = data['array']
    debug("session on dc", session)
    debug("sessiondc", session["dc"])
    return 'okay'
'''

'''# variableChooserSecondStep()
@app.route('/variableChooserSecondStep', methods=['POST'])
def processvcss():
    ###
    global vcss
    vcss = []
    data = request.get_json()
    vcss = data['array']
    ###
    data = request.get_json()
    session["vcss"] = data['array']
    debug("session on vcss", session)
    return 'okay' # replace'''

'''# datasetChooserSecondStep()
@app.route('/datasetChooserSecondStep', methods=['POST'])
def processdcss():
    ###
    global dcss
    dcss = []
    data = request.get_json()
    dcss = data['array']
    ###
    # session["dcss"] = []
    data = request.get_json()
    session['dcss'] = data['array']
    debug("session on dcss", session)
    return 'okay'
'''

# variableChooser()
@app.route('/vdchooser_fs', methods=['POST'])
def processvc():
    data = request.get_json()
    session["vc"] = data['array_vars']
    session["dc"] = data["array_datasets"]
    debug("session on vdchooserfs", session)
    return ''
    

# variableChooserSecondStep()
@app.route('/vdchooser_ss', methods=['POST'])
def processvcss():
    data = request.get_json()
    session["vcss"] = data['array_vars']
    session["dcss"] = data["array_datasets"]
    debug("session on vdchooserss", session)
    return 'okay' # replace

# creates the merged dataset for the first step
@app.route('/createDf/', methods=['POST', "GET"])
def create_df():
    debug("session on createDf", session)
    dc = session["dc"]
    vc = session["vc"]

    debug("vc", vc)
    debug("dc", dc)
  
    print("creating dataframe")
    i = 0
    while i < len(dc):
        if dc[i] is None:
            dc = dc[:i] + dc[i+1:]
        else:
            i += 1
    i = 0
    while i < len(vc):
        if vc[i] is None:
            vc = vc[:i] + vc[i+1:]
        else:
            i += 1
    if "user" in session:
        dataframe = data_merger.createNewDataList(dc, vc, session["user"]) # datasetChooser, variableChooser
    else:
        dataframe = data_merger.createNewDataList(dc, vc, "test_profile") # datasetChooser, variableChooser
    dataframe = dataframe.drop(["eventID"], axis = 1)
    sample = dataframe.loc[:999]
    stateabb_vals = []
    stateabb1_vals = []
    stateabb2_vals = []
    if "stateabb" in dataframe.columns:
        dataframe['ccode'] = dataframe['ccode'].astype(str)
        stateabb_values = dataframe['stateabb'].unique()
        stateabb_vals = sorted(stateabb_values)
    if "stateabb1" in dataframe.columns:
        stateabb1_values = dataframe['stateabb1'].unique()
        stateabb1_vals = sorted(stateabb1_values)
    if "stateabb2" in dataframe.columns:
        stateabb2_values = dataframe['stateabb2'].unique()
        stateabb2_vals = sorted(stateabb2_values)

    if len(stateabb_vals) > 0:
        state_columns_dict = {'stateabb': stateabb_vals}
        state_columns = pd.DataFrame(data=[state_columns_dict])
    elif (len(stateabb1_vals) > 0) & (len(stateabb2_vals) >0):
        state1_columns_dict = {'stateabb1': stateabb1_vals} 
        state2_columns_dict = {'stateabb2': stateabb2_vals}
        state_columns1 = pd.DataFrame(data=[state1_columns_dict])
        state_columns2 = pd.DataFrame(data=[state2_columns_dict])
    print("converting to json...")
    new_df = sample.to_json(orient="records")


    if "user" in session:
        csv_file_path = config["UPLOAD_FOLDER"] + "/" + session["user"] + "/temp/temp.csv"
        print("dbg.csv_file_path = " + csv_file_path)
        os.makedirs(os.path.dirname(csv_file_path), exist_ok=True)
        dataframe.to_csv(csv_file_path, index=False)
    if len(stateabb_vals) > 0:
        response = {
            "message": "data processing successful",
            "status": 200,
            "new_df": new_df,
            "state_columns": state_columns.to_json(orient = "values")
        }
    elif (len(stateabb1_vals) > 0) & (len(stateabb2_vals) >0):
        response = {
            "message": "data processing successful",
            "status": 200,
            "new_df": new_df,
            "state_columns1": state_columns1.to_json(orient = "values"),
            "state_columns2": state_columns2.to_json(orient = "values")
        }
    return response

@app.route("/locktest")
def locktest():
    logging.info("Request received, attempting to acquire lock.")
    acquired = route_lock.acquire(blocking=False)
    if acquired:
        try:
            
            logging.info("Lock acquired, processing...")
            time.sleep(30)
            logging.info("Processing complete, releasing lock.")
            return "DataFrame created or modified successfully"
        finally:
            route_lock.release()
            logging.info("Lock released.")
    else:
        logging.info("Could not acquire lock, resource is busy.")
        return "Resource is busy, please try in a moment", 429

# gets state columns for state filters
@app.route('/getStateColumns', methods=['POST', "GET"])
def getStateColumns():
    temp_csv_path = os.path.join(config["UPLOAD_FOLDER"], session["user"], 'temp', 'temp.csv')
    dataframe = pd.read_csv(temp_csv_path)

    stateabb_vals = []
    stateabb1_vals = []
    stateabb2_vals = []
    if "stateabb" in dataframe.columns:
        stateabb_values = dataframe['stateabb'].unique()
        stateabb_vals = sorted(stateabb_values)
    if "stateabb1" in dataframe.columns:
        stateabb1_values = dataframe['stateabb1'].unique()
        stateabb1_vals = sorted(stateabb1_values)
    if "stateabb2" in dataframe.columns:
        stateabb2_values = dataframe['stateabb2'].unique()
        stateabb2_vals = sorted(stateabb2_values)
    if len(stateabb_vals) > 0:
        state_columns_dict = {'stateabb': stateabb_vals}
        state_columns = pd.DataFrame(data=[state_columns_dict])
        print(state_columns)
    elif (len(stateabb1_vals) > 0) & (len(stateabb2_vals) >0):
        state1_columns_dict = {'stateabb1': stateabb1_vals} 
        state2_columns_dict = {'stateabb2': stateabb2_vals}
        state_columns1 = pd.DataFrame(data=[state1_columns_dict])
        state_columns2 = pd.DataFrame(data=[state2_columns_dict])
        print(state_columns1)
    if len(stateabb_vals) > 0:
        response = {
            "message": "data processing successful",
            "status": 200,
            "state_columns": state_columns.to_json(orient = "values")
        }
    elif (len(stateabb1_vals) > 0) & (len(stateabb2_vals) > 0):
        response = {
            "message": "data processing successful",
            "status": 200,
            "state_columns1": state_columns1.to_json(orient = "values"),
            "state_columns2": state_columns2.to_json(orient = "values")
        }
    return response

#gets dataframe for the back button
@app.route('/backbutton2/', methods=['POST', "GET"])
def back_button_2():
    temp_csv_path = os.path.join(config["UPLOAD_FOLDER"], session["user"], 'temp', 'temp.csv')
    dataframe = pd.read_csv(temp_csv_path)
    sample = dataframe.loc[:999]
       
    print("converting to json...")
    new_df = sample.to_json(orient="records")
    response = {
        "message": "data processing successful",
        "status": 200,
        "new_df": new_df
    }
    return response

# creates a table for the second table of data
@app.route('/createDfSS/', methods=['POST', "GET"])
def create_df_secondstep():
    temp_csv_path = os.path.join(config["UPLOAD_FOLDER"], session["user"], 'temp', 'temp.csv')
    dataframe = pd.read_csv(temp_csv_path)
    dataframe2 = pd.read_csv(temp_csv_path)
    debug("session on createDfSS", session)
    dcss = session['dcss']
    vcss = session['vcss']
    dc = session["dc"]
    vc = session["vc"]
    if "user" in session:
        dataframe2 = data_merger.createNewDataListSecondStep(dataframe, dcss, vcss, dc, vc, session["user"]) # datasetChooser, variableChooser
    else:
        dataframe2 = data_merger.createNewDataListSecondStep(dataframe, dcss, vcss, dc, vc, "test_profile")
    dataframe2 = dataframe2.drop(["eventID_state2"], axis = 1)
    dataframe2 = dataframe2.drop(["eventID_state1"], axis = 1)
    sample2 = dataframe2.loc[:999]
    print("converting to json...")
    new_df = sample2.to_json(orient="records")

    if "user" in session:
        csv_file_path = config["UPLOAD_FOLDER"] + "/" + session["user"] + "/temp/temp.csv"
        print("dbg.csv_file_path = " + csv_file_path)
        os.makedirs(os.path.dirname(csv_file_path), exist_ok=True)
        dataframe2.to_csv(csv_file_path, index=False)
    
    response = {
        "message": "data processing successful",
        "status": 200,
        "new_df": new_df
    }
    return response

@app.route("/displayData.html", methods=["POST", "GET"])
def goto_displayData():
    if request.method == 'POST':
        return render_template("displayData.html")
    else:
        # makes no sense to be at this page without hitting the "generate" button
        return render_template("error")

#filters the data based on the user's inputs
@app.route('/filterData', methods=['POST'])
def processfilters():
    debug("filter data", "called")
    data = request.get_json()
    debug("filter data", data)
    filters = data['array']
    debug("filter filters", filters)
    session["yearMin"] = filters[0]
    session["yearMax"] = filters[1]
    session["stateOneFilter"] = filters[2]
    session["stateTwoFilter"] = filters[3]
    return 'okay'

def create_citation_txt(dataset_names, citations):
    output = ""
    for dataset in dataset_names:
        citation = citations.get(dataset)
        if citation:
            output += f"{dataset}: {citation}\n"
        else:
            output += f"{dataset}: Citation not found\n"
    return output

@app.route('/downloadCitations/', methods=['POST', "GET"])
def downloadCitations():
    if "user" not in session:
        flash("You must be logged in to download citations.")
        return redirect(url_for("login"))
    citations = load_citations_from_json(os.path.join(config["BASE"], "citations.json"))
    debug("datasets used", session["dc"])
    debug("all citations", citations)
    citations_text = create_citation_txt(session["dc"], citations)
    
    # Convert the string to a BytesIO object
    buffer = io.BytesIO()
    buffer.write(citations_text.encode('utf-8'))
    buffer.seek(0)
    today = datetime.now()
    return send_file(buffer, as_attachment=True, download_name=f"citations_{today.strftime('%Y%m%d_%H%M%S')}.txt", mimetype='text/plain')

#allows the user to download dataframe after filter-processing
@app.route('/downloadDf/', methods=['POST', "GET"])
def downloadCSV():
    dc = session["dc"]
    debug("downloadDf", "called")
    if "user" not in session:
        flash("You must be logged in to download CSV files.")
        return redirect(url_for("login"))
    chng_df = pd.read_csv(config["UPLOAD_FOLDER"] + "/" + session["user"] + "/temp/temp.csv")
    today = datetime.now()

    if session["yearMin"] == "":
        session["yearMin"] = 1000
    if session["yearMax"] == "":
        session["yearMax"] = 3000

    if (len(session["stateOneFilter"]) != 0) & ("stateabb" in chng_df.columns):
        chng_df = chng_df[chng_df['stateabb'].isin(session["stateOneFilter"])]
    elif (len(session["stateOneFilter"]) != 0) & ("stateabb1" in chng_df.columns):
        chng_df = chng_df[chng_df['stateabb1'].isin(session["stateOneFilter"])]
    if (len(session["stateTwoFilter"]) != 0) & ("stateabb2" in chng_df.columns):
        chng_df = chng_df[chng_df['stateabb2'].isin(session["stateTwoFilter"])]
    chng_df = chng_df.loc[(chng_df['year'] >= int(session["yearMin"])) & (chng_df['year'] <= int(session["yearMax"]))] 
    print("csv converted")
    return Response(
       chng_df.to_csv(),
       mimetype="text/csv",
       headers={"Content-disposition":
       "attachment; filename=cowplus_online_"+str(today.year) + str(today.month) + str(today.day) + "_" + str(today.hour) + "_" + str(today.minute) + "_" + str(today.second) + ".csv"})

@app.route("/enable_refresh")
def enable_refresh_page():
    enable_refresh()
    return "<p>refresh enabled</p>"
    

# run

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, ssl_context=None)