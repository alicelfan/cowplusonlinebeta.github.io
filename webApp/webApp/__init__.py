from flask import Flask, cli, Response, flash, render_template, request, redirect, url_for, request, jsonify, session, make_response, send_from_directory
from werkzeug.utils import secure_filename
from datetime import *
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_mail import Mail, Message
from flask_bootstrap import Bootstrap

from flask_bcrypt import Bcrypt
import sys
from email.message import EmailMessage
import ssl
import smtplib
import csv
import pandas as pd
import numpy as np
import logging
# new imports
import io
import time
import threading
from threading import Lock
import queue
sys.path.append('C:\cowplusonlinebeta.github.io\webApp\webApp')
import openconfig
from flask import request
from functools import wraps

import os

from datetime import date
from datetime import datetime
import shutil
current_dir = os.path.dirname(os.path.abspath(__file__))
ALLOWED_EXTENSIONS = {'txt', 'csv'}
python_files_dir = os.path.join(current_dir, 'python_files')
upload_files_dir = os.path.join(current_dir, 'datafiles_csv')
config = openconfig.read_config()
citations = {}
with open(config['BASE'] + "/citations.txt", 'r') as file:
    for line in file:
        if "#" not in line:
            key, value = line.strip().split('=')
            citations[key] = value

# UPLOAD_FOLDER , SQLALCHEMY_DATABASE_URI

logging.basicConfig(level=logging.INFO)
app = Flask(__name__, template_folder='templates')
Bootstrap(app)
app.secret_key = "dJL1bnnSOCDi2Brtt04x"
app.config['UPLOAD_FOLDER'] = config['UPLOAD_FOLDER']
app.config['SQLALCHEMY_DATABASE_URI'] = config['SQLALCHEMY_DATABASE_URI']
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.permanent_session_lifetime = timedelta(minutes=60)
import random
import re

def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

db = SQLAlchemy(app)
migrate = Migrate(app, db)
mail = Mail(app)
bcrypt = Bcrypt(app)
task_queue = queue.Queue()
route_lock = Lock()

# TASK WORKER FOR ACTIONS THAT REQUIRE NON CONCURRENCE
def task_worker():
    while True:
        # get the next task; this is blocking if the queue is empty
        task_func = task_queue.get()
        try:
            task_func()
        finally:
            # signal that the task is done
            task_queue.task_done()

worker_thread = threading.Thread(target=task_worker)
worker_thread.daemon = True  # Daemon threads exit when the program does
worker_thread.start()

class users(db.Model):
    _id = db.Column("id", db.Integer, primary_key=True)
    name = db.Column("name", db.String(100))
    email = db.Column("email", db.String(100))
    password = db.Column("password", db.String(100))
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    is_confirmed = db.Column(db.Boolean, nullable=False, default=False)
    confirmed_on = db.Column(db.DateTime, nullable=True)

    def __init__(self, name, email, password, is_admin=False, is_confirmed=False, confirmed_on=None):
        self.name = name
        self.email = email
        self.password = password
        self.is_admin = is_admin
        self.is_confirmed = is_confirmed
        self.confirmed_on = confirmed_on

vc = []
vc2 = []
dc = []
vcss = []
dcss = []

email_sender = "cowplusnoreply@gmail.com"
email_password = "rkjhjkvetassfwkx"

m_files = []
d_files = []
all_d_files = []
all_m_files = []

m_files_shared = []
d_files_shared = []
all_d_files_shared = []
all_m_files_shared = []
# local path []
sys.path.append(python_files_dir)
import variables
import upload
import data_merger

# -- routes -- #

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
        )
        db.session.add(user)
        db.session.commit()
        print(f"Admin with name {nm} and email {em} created successfully!")
    except Exception as e:
        print("Couldn't create admin user.")
        print(e)

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

@app.route("/")
def home():
    return redirect("/index.html")

def logip():
    ip_address = request.remote_addr
    logging.debug(f"/reset request from {ip_address},", session["user"])
    return

@app.route("/reset", methods=['POST'])
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
    return redirect("/panel")

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
        flash("You are not logged in!")
        return redirect("/login")
# needs verification... @alice
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
                    return redirect(url_for('download_file', name=filename))
            return render_template("upload.html")
        else:
            return redirect(url_for("verify"))
    else:
        flash("You are not logged in!")
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
        print("user in session")
        directory_to_check = config["UPLOAD_FOLDER"] + "/" + session["user"]
        if not os.path.isdir(directory_to_check):
            os.makedirs(directory_to_check)
    else:
        print("no user in session")
        directory_to_check = config["UPLOAD_FOLDER"] + "/test_profile"
    if not os.path.isdir(directory_to_check):
        os.makedirs(directory_to_check)
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

@app.route('/verifyFunction/', methods=['POST', 'GET'])  
def verifyFunction():
    global files
    global m_files, d_files, g_files, b_files
    global all_m_files, all_d_files
    verified = False
    # Get the list of files from webpage
    files = request.files.getlist("file")
    print(files)
    os.chdir(config["UPLOAD_FOLDER"])
    # Iterate for each file in the files List, and Save them
    if files[0].filename != "":
        for file in files:
           file.save(file.filename)
        m_files, d_files, g_files, b_files = upload.verify_files(files)
        if(len(b_files) == 0):
            verified = True
        for f in g_files:
            os.remove(f)
        for f in b_files:
            os.remove(f)
    if(len(files) == 0):
        verified = False
    response = {
        "message": "data processing successful",
        "status": 200,
        "good_files": g_files,
        "bad_files": b_files,
        "verification": verified
    }
    
    return response

@app.route('/uploadFunction/', methods = ['POST', 'GET'])
def uploadFunction():
    global all_m_files, all_d_files, m_files, d_files
    for m in m_files:
        all_m_files.append(m)
    for d in d_files:
        all_d_files.append(d)
    files = request.files.getlist("file")
    username = session["user"]
    directory_to_check = config["UPLOAD_FOLDER"] + "/" + username
    if not os.path.isdir(directory_to_check):
        os.makedirs(directory_to_check)
    os.chdir(os.path.join(config["UPLOAD_FOLDER"], username))
    for file in files:
        file.save(file.filename)
        print("saved")
    m_files = []
    d_files = []
    g_files = []
    b_files = []
    return redirect('/upload.html')

@app.route('/verifyFunctionShared/', methods=['POST', 'GET'])  
def verifyFunctionShared():
    global files_shared
    global m_files_shared, d_files_shared, g_files_shared, b_files_shared
    global all_m_files_shared, all_d_files_shared
    verified = False
    # Get the list of files from webpage
    files_shared = request.files.getlist("file")
    print(files_shared)
    os.chdir(app.config['UPLOAD_FOLDER'].replace("datafiles_csv", "datasets_shared"))
    # Iterate for each file in the files List, and Save them
    if files_shared[0].filename != "":
        for file in files_shared:
           file.save(file.filename)
        m_files_shared, d_files_shared, g_files_shared, b_files_shared = upload.verify_files(files_shared)
        if(len(b_files_shared) == 0):
            verified = True
        for f in g_files_shared:
            os.remove(f)
        for f in b_files_shared:
            os.remove(f)
    if(len(files_shared) == 0):
        verified = False
    response = {
        "message": "data processing successful",
        "status": 200,
        "good_files": g_files_shared,
        "bad_files": b_files_shared,
        "verification": verified
    }
    
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
            else:
                flash("Password incorrect.")
                return redirect(url_for("login"))
        elif found_email:
            if bcrypt.check_password_hash(found_email.password, pwd):
                session["user"] = found_email.name
                session["email"] = user
                session["is_admin"] = found_email.is_admin
                session["verified"] = found_email.is_confirmed
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

@app.route("/signup.html", methods=["POST", "GET"])
def signup():
    if request.method == "POST":
        log("signup")
        session.permanent = True
        user = request.form["nm"]
        em = request.form["em"]
        pwd = request.form['pwd']

        if len(user) > 20 or not user.isalnum():
            flash("Username must be 20 characters or fewer and must contain only numbers and letters.")
            return render_template("signup.html")

        if len(pwd) < 8 or not re.search("[a-zA-Z]", pwd) or not re.search("[0-9]", pwd):
            flash("Password must be at least 8 characters long and include both letters and numbers.")
            return render_template("signup.html")

        found_user = users.query.filter_by(name=user).first()
        found_email = users.query.filter_by(email=em).first()

        if found_user or found_email:
            flash("User already exists.")
            return render_template("signup.html")
        
        if user and em and pwd:
            if "@" in em and "." in em:
                hashed_pwd = bcrypt.generate_password_hash(pwd).decode('utf-8')
                usr = users(name=user, email=em, password=hashed_pwd)  # assuming the 'users' model takes these parameters
                db.session.add(usr)
                db.session.commit()
                
                session["user"] = user
                session["email"] = em
                session["verified"] = False
                
                os.mkdir(os.path.join(config["UPLOAD_FOLDER"], session["user"]))
                
                flash("User created")
                return redirect(url_for("verify"))
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
                    return redirect(url_for("user"))
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
file_contents = []
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

def remove_items(test_list, item):
 
    # using list comprehension to perform the task
    res = [i for i in test_list if i != item]
    return res

@app.route("/shared.html", methods=["POST", "GET"])
def importpage():
    IMPORT_FOLDER = app.config['UPLOAD_FOLDER'].replace("datafiles_csv", "datasets_shared")
    global file_contents, user_files
    global all_m_files_shared, all_d_files_shared, m_files_shared, d_files_shared
    print("dbg: IMPORT_FOLDER = " + IMPORT_FOLDER)
    if request.method == 'POST':
        author_name = request.form['author_name']
        article_title = request.form['article_title']
        title = request.form['title']
        inclusive_pages = request.form['inclusive_pages']
        volume = request.form['volume']
        issue = request.form['issue']
        year = request.form['year']
        month = request.form['month']
        for m in m_files_shared:
            all_m_files_shared.append(m)
        for d in d_files_shared:
            all_d_files_shared.append(d)
        if 'file' in request.files:
            files = request.files.getlist('file')
            for file in files:
                if file.filename == '':
                    continue
                if file.filename == 'test_dyadic.csv':
                    continue
                if file.filename == 'test_monadic.csv':
                    continue
                ###
                filename = secure_filename(file.filename)
                file.save(os.path.join(IMPORT_FOLDER, filename))
                ###
                # Read the content of the file and store it
                stream = StringIO(file.stream.read().decode("UTF8"), newline=None)
                csv_input = csv.reader(stream)
                file_data = list(csv_input)
                # to change; have individuals put manual citations.
                citation = create_chicago_citation({
                        'author_name': author_name,
                        'article_title': article_title,
                        'title': title,
                        'inclusive_pages': inclusive_pages,
                        'volume': volume,
                        'issue': issue,
                        'year': year,
                        'month': month
                    })
                to_append = filename + "=" + citation
                print("dbg.to_append = " + to_append)

                append_to_file(filename, citation, config["BASE"] + "/citations.txt")

    m_files_shared = []
    d_files_shared = []
    g_files_shared = []
    b_files_shared = [] 
    files_wtest = os.listdir(IMPORT_FOLDER)
    files_wtm = remove_items(files_wtest, "test_monadic.csv")
    files = remove_items(files_wtm, "test_dyadic.csv")
    file_contents = [{'filename': f} for f in files]
    
    return render_template("/shared.html", file_contents=file_contents)

@app.route("/preview", methods=["POST", "GET"])
def preview():
    if request.method == "POST":
        filename = request.form['filename']
    # Construct the full file path
    file_path = config["BASE"] + "/datasets_shared/" + filename
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
    
    # Render the HTML table
    html = f"""
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
        <title>CSV Preview</title>
      </head>
      <body>
        <div class="container">
          <h1 class="mt-5">Preview of {filename} (first 100 rows)</h1>
          <div class="table-responsive">
            {html_table}
          </div>
        </div>
      </body>
    </html>
    """
    
    return html

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
            
            copy_file_to_folder(file_path, destination_folder)
            flash(f"Successfully imported {filename}")
            return redirect(url_for('importpage'))
        except Exception as e:
            return f"An error occurred: {e}"
        
    else:
        flash("You must be logged in to import data.")
        return redirect(url_for('login'))
    

@app.route("/delete", methods=["POST"])
def delete_file():
    global file_contents, user_files
    filename_to_delete = request.form['filename']
    directory = config["BASE"] + "/datasets_shared"
    
    # Construct the full file path
    file_path = os.path.join(directory, filename_to_delete)
    
    try:
        # Check if file exists
        if os.path.exists(file_path):
            os.remove(file_path)
            flash(f"File '{filename_to_delete}' deleted successfully")
            return redirect(url_for('importpage'))
        else:
            return f"File '{filename_to_delete}' not found", 404
    except Exception as e:
        return str(e), 500

@app.route("/download", methods=["POST"])
def download_file():
    filename_to_download = request.form['filename']
    print("dbg.filename = " + filename_to_download)
    # Define the directory where the files are located
    directory = config["BASE"] + "/datasets_shared"
    try:
        return send_from_directory(directory, filename_to_download, as_attachment=True)
    except FileNotFoundError:
        return "File not found", 404
    return redirect(url_for('importpage'))

@app.route("/user", methods=["POST", "GET"])
def user():
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
        return render_template("user.html", email=email)
    else:
        return redirect(url_for("login"))

@app.route("/logout")
def logout():
    log("logout")
    session.pop("user", None)
    session.pop("email", None)
    session.pop("is_admin", None)
    session.pop("verified", None)
    flash("Logged out successfully.")
    return redirect(url_for("login"))

def getVarJSONs():
    global a_var_id_json, m_var_id_json, a_var_name_json, m_var_name_json, a_var_descrip_json, m_var_descrip_json, a_var_dataset_json, m_var_dataset_json
    if "user" in session:
        a_var_id_json, m_var_id_json = variables.createVarIDs_JS(session["user"])
        a_var_name_json, m_var_name_json = variables.createVar_JS(session["user"])
        a_var_descrip_json, m_var_descrip_json = variables.createVarDescrip_JS(session["user"])
        a_var_dataset_json, m_var_dataset_json = variables.createVarDataset_JS(session["user"])
    else:
        a_var_id_json, m_var_id_json = variables.createVarIDs_JS("test_profile")
        a_var_name_json, m_var_name_json = variables.createVar_JS("test_profile")
        a_var_descrip_json, m_var_descrip_json = variables.createVarDescrip_JS("test_profile")
        a_var_dataset_json, m_var_dataset_json = variables.createVarDataset_JS("test_profile")


@app.route('/firstStepVarJSON/', methods=['POST', "GET"])
def firstStepVarJSON():
    getVarJSONs() 
    var_id_json = a_var_id_json
    var_name_json = a_var_name_json
    var_descrip_json = a_var_descrip_json
    var_dataset_json = a_var_dataset_json
    response = {
        "message": "vars",
        "status": 200,
        "name_json": var_name_json,
        "descrip_json": var_descrip_json,
        "var_id_json": var_id_json,
        "dataset_json": var_dataset_json
    }
    return response

@app.route('/secondStepVarJSON/', methods=['POST', "GET"])
def secondStepVarJSON():
    var_id_json = m_var_id_json
    var_name_json = m_var_name_json
    var_descrip_json = m_var_descrip_json
    var_dataset_json = m_var_dataset_json
    response = {
        "message": "vars",
        "status": 200,
        "name_json": var_name_json,
        "descrip_json": var_descrip_json,
        "var_id_json": var_id_json,
        "dataset_json": var_dataset_json
    }
    return response
# variableChooser()
@app.route('/variableChooser', methods=['POST'])
def processvc():
    global vc
    data = request.get_json()
    vc = data['array']
    print()
    return ''

@app.route('/variableChooser2', methods=['POST'])
def processvc2():
    global vc
    data = request.get_json()
    t = data['array']
    vc = vc + t
    return ''

# datasetChooser()
@app.route('/datasetChooser', methods=['POST'])
def processdc():
    global dc
    data = request.get_json()
    dc = data['array']
    return 'okay'

# variableChooserSecondStep()
@app.route('/variableChooserSecondStep', methods=['POST'])
def processvcss():
    global vcss
    vcss = []
    data = request.get_json()
    vcss = data['array']
    return 'okay' # replace

# datasetChooserSecondStep()
@app.route('/datasetChooserSecondStep', methods=['POST'])
def processdcss():
    global dcss
    dcss = []
    data = request.get_json()
    dcss = data['array']
    return 'okay'

@app.route('/createDf/', methods=['POST', "GET"])
def create_df():
    global dataframe
    global dataframe2

    global dc
    global vc
    
    print("creating dataframe")
    if route_lock.acquire(blocking=False):
        try:
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
                csv_file_path = config["UPLOAD_FOLDER"] + "/" + session["user"] + "/temp.csv"
                print("dbg.csv_file_path = " + csv_file_path)
                os.makedirs(os.path.dirname(csv_file_path), exist_ok=True)
                sample.to_csv(csv_file_path, index=False)

            dataframe2 = dataframe.copy(deep = True)
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
        finally:
            route_lock.release()
        return response
    else:
        print("dbg: resource busy; lock engaged")
        return redirect("busy.html")

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
@app.route('/getStateColumns', methods=['POST', "GET"])
def getStateColumns():
    global dataframe
    global dataframe2

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
    elif (len(stateabb1_vals) > 0) & (len(stateabb2_vals) >0):
        state1_columns_dict = {'stateabb1': stateabb1_vals} 
        state2_columns_dict = {'stateabb2': stateabb2_vals}
        state_columns1 = pd.DataFrame(data=[state1_columns_dict])
        state_columns2 = pd.DataFrame(data=[state2_columns_dict])
    if len(stateabb_vals) > 0:
        response = {
            "message": "data processing successful",
            "status": 200,
            "state_columns": state_columns.to_json(orient = "values")
        }
    elif (len(stateabb1_vals) > 0) & (len(stateabb2_vals) >0):
        response = {
            "message": "data processing successful",
            "status": 200,
            "state_columns1": state_columns1.to_json(orient = "values"),
            "state_columns2": state_columns2.to_json(orient = "values")
        }
    return response

@app.route('/backbutton2/', methods=['POST', "GET"])
def back_button_2():
    global dataframe
    global dataframe2
    sample = dataframe.loc[:999]
       
    print("converting to json...")
    new_df = sample.to_json(orient="records")
    response = {
        "message": "data processing successful",
        "status": 200,
        "new_df": new_df
    }
    return response

@app.route('/createDfSS/', methods=['POST', "GET"])
def create_df_secondstep():
    global dataframe
    global dataframe2
    if "user" in session:
        dataframe2 = data_merger.createNewDataListSecondStep(dataframe, dcss, vcss, dc, vc, session["user"]) # datasetChooser, variableChooser
    else:
        dataframe2 = data_merger.createNewDataListSecondStep(dataframe, dcss, vcss, dc, vc, "test_profile")
    dataframe2 = dataframe2.drop(["eventID_state2"], axis = 1)
    sample2 = dataframe2.loc[:999]
    print("converting to json...")
    new_df = sample2.to_json(orient="records")

    if "user" in session:
        csv_file_path = config["UPLOAD_FOLDER"] + "/" + session["user"] + "/temp.csv"
        print("dbg.csv_file_path = " + csv_file_path)
        os.makedirs(os.path.dirname(csv_file_path), exist_ok=True)
        sample2.to_csv(csv_file_path, index=False)
    
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

@app.route('/filterData', methods=['POST'])
def processfilters():
    global yearMin, yearMax, stateOneFilter, stateTwoFilter
    data = request.get_json()
    filters = data['array']
    yearMin = filters[0]
    yearMax = filters[1]
    stateOneFilter = filters[2]
    stateTwoFilter = filters[3]
    return 'okay'

@app.route('/test/', methods=['GET'])
def test_download():
    df = pd.DataFrame({
        'Column1': [1, 2, 3],
        'Column2': [4, 5, 6]
    })

    csv_content = df.to_csv(index=False)
    response = make_response(csv_content)
    response.headers['Content-Disposition'] = "attachment; filename=test_data.csv"
    response.headers['Content-Type'] = 'text/csv'
    return response

@app.route('/downloadCitations/', methods=['POST', "GET"])
def downloadCitations():
    if "user" not in session:
        flash("You must be logged in to download citations.")
        return redirect(url_for("login"))
    print("dbg.dc: " + str(dc))
    citations_text = "\n".join([f"{citations[name]}" for name in dc if name in citations])
    
    # Convert the string to a BytesIO object
    buffer = io.BytesIO()
    buffer.write(citations_text.encode('utf-8'))
    buffer.seek(0)
    today = datetime.now()
    return send_file(buffer, as_attachment=True, download_name=f"citations_{today.strftime('%Y%m%d_%H%M%S')}.txt", mimetype='text/plain')


@app.route('/downloadDf/', methods=['POST', "GET"])
def downloadCSV():
    global dataframe2, chng_df, yearMin, yearMax, stateOneFilter, stateTwoFilter, dc
    if "user" not in session:
        flash("You must be logged in to download CSV files.")
        return redirect(url_for("login"))
    chng_df = pd.read_csv(config["UPLOAD_FOLDER"] + "/" + session["user"] + "/temp.csv")
    today = datetime.now()
    if yearMin == "":
        yearMin = 1000
    if yearMax == "":
        yearMax = 3000
    if (len(stateOneFilter) != 0) & ("stateabb" in chng_df.columns):
        chng_df = chng_df[chng_df['stateabb'].isin(stateOneFilter)]
    elif (len(stateOneFilter) != 0) & ("stateabb1" in chng_df.columns):
        chng_df = chng_df[chng_df['stateabb1'].isin(stateOneFilter)]
    if (len(stateTwoFilter) != 0) & ("stateabb2" in chng_df.columns):
        chng_df = chng_df[chng_df['stateabb2'].isin(stateTwoFilter)]
    chng_df = chng_df.loc[(chng_df['year'] >= int(yearMin)) & (chng_df['year'] <= int(yearMax))] 
    print("csv converted")
    return Response(
       chng_df.to_csv(),
       mimetype="text/csv",
       headers={"Content-disposition":
       "attachment; filename=cowplus_online_"+str(today.year) + str(today.month) + str(today.day) + "_" + str(today.hour) + "_" + str(today.minute) + "_" + str(today.second) + ".csv"})

# generic for all req. to save code

# -- TEST FUNCTIONS. THESE SERVE NO PURPOSE IN THE FINAL PROGRAM AND SHOULD BE DELETED IN THE FUTURE. -- #

@app.route("/chooseDataset.html", methods=["POST", "GET"])
def goto_chooseDataset():
    if request.method == 'POST':
        data_group = request.form.get('dataGroup')
        if data_group == 'countryYear':
            print("cy")
        elif data_group == "dyadYear":
            print("dy")
        else:
            print("no selection was made")
        return render_template("chooseDataset.html")
    else:
        return render_template("chooseDataset.html")


# run

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)