from flask import Flask, render_template, redirect, url_for, request, session, jsonify,flash,make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from datetime import datetime, timedelta,timezone, UTC,time
from urllib.parse import quote
from apscheduler.schedulers.background import BackgroundScheduler
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy.sql import func, and_ ,or_
from functools import wraps
from werkzeug.utils import secure_filename
import random
import os
import requests
import pandas as pd
import csv
import qrcode
from io import BytesIO
from base64 import b64encode
from pytz import timezone 
import atexit
from cryptography.fernet import Fernet
# import time
import json
import traceback
app = Flask(__name__)
UPLOAD_FOLDER = 'static/uploads/'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg'}
CSV_EXTENSIONS = {'csv'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


ist = timezone('Asia/Kolkata')
def allowed_file(filename, extensions=IMAGE_EXTENSIONS):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in extensions

app.secret_key = "Shannu"
serializer = URLSafeTimedSerializer(app.secret_key)
# app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)  # Session lasts 1 hour
app.config['SESSION_COOKIE_HTTPONLY'] = True
# Make session permanent
password = "@Ppk200404k"
escaped_password = quote(password)
# Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv("EMAIL")  # Update with your email
app.config['MAIL_PASSWORD'] = os.getenv("EMAIL_APP_PASSWORD") # Update with your app password

mail = Mail(app)
ist = timezone('Asia/Kolkata')
# Database Configuration

# app.config["SQLALCHEMY_DATABASE_URI"] = f"postgresql://postgres:{escaped_password}@localhost:5000/users"
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://sasiusers_user:KbF29ulqMKOcPGRVqzUSeF4kSbo5ax1A@dpg-cvft1nofnakc739rm4og-a.oregon-postgres.render.com/sasiusers"


app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
# app.config["SQLALCHEMY_BINDS"] = {
#     "new_db": f"postgresql://postgres:{escaped_password}@localhost:5000/faculty_db",  # PostgreSQL for faculty
#     "perm_db": f"postgresql://postgres:{escaped_password}@localhost:5000/permissions_db"   # PostgreSQL for permissions
# }

db = SQLAlchemy(app)

app.config['ADMIN_USERNAME'] = os.getenv('ADMIN_USERNAME')
app.config['ADMIN_PASSWORD'] = os.getenv('ADMIN_PASSWORD')

app.config['ENCRYPTION_KEY'] = Fernet.generate_key()
cipher_suite = Fernet(app.config['ENCRYPTION_KEY'])

# User table model
class User(db.Model):
    regd = db.Column(db.String(80), primary_key=True, nullable=False)  # Username & Password
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=True)
    gender = db.Column(db.String(30), nullable=True, default='not prefer to say')
    email = db.Column(db.String(120), unique=True, nullable=False)
    dept = db.Column(db.String(10), nullable=False)
    student_phone = db.Column(db.String(15), nullable=False)
    parent_phone = db.Column(db.String(15), nullable=False)  # New field
    address = db.Column(db.String(150), nullable=False)
    password = db.Column(db.String(256), nullable=False)  # Hashed password
    photo = db.Column(db.String(150), nullable=True)  # Photo path
    category = db.Column(db.String(20), nullable=False)
    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)


class Faculty(db.Model):
    
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True,primary_key=True, nullable=False)
    dept = db.Column(db.String(50), nullable=False)
    faculty_phone = db.Column(db.String(10), unique=True, nullable=False)
    room_no=db.Column(db.String(10), nullable=False)
    category = db.Column(db.String(50), nullable=False)  #HOD, incharge, admin
    password_hash = db.Column(db.String(255), nullable=False)
    photo = db.Column(db.String(255), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    

class PermissionRequest(db.Model):
    __tablename__ = "permission_request"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    student_regd = db.Column(db.String(80), nullable=False)
    student_name = db.Column(db.String(100), nullable=False)
    student_email = db.Column(db.String(120), nullable=False)
    dept = db.Column(db.String(10), nullable=False)
    permission_type = db.Column(db.String(10), nullable=False)
    start_time = db.Column(db.String(10), nullable=True)
    end_time = db.Column(db.String(10), nullable=True)
    start_date = db.Column(db.String(10), nullable=True)
    end_date = db.Column(db.String(10), nullable=True)
    reason = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(10), default='Pending')
    hod_status = db.Column(db.String(10), default='Pending')
    incharge_status = db.Column(db.String(10), default='Pending')
    hod_message = db.Column(db.Text, default='NIL')
    incharge_message = db.Column(db.Text, default='NIL')
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(ist))
    check_in_time = db.Column(db.DateTime, nullable=True)
    check_out_time = db.Column(db.DateTime, nullable=True)
    is_processed = db.Column(db.Boolean, default=False)
    is_resolved = db.Column(db.Boolean, default=False)
    letter_path = db.Column(db.String(255), nullable=True) 
    notification_sent = db.Column(db.Boolean, default=False)
def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'username' not in session:
                return redirect(url_for('home'))  # Redirect to home if not logged in
            
            if role and session.get('category') != role:
                return redirect(url_for('home'))  # Redirect if role doesn't match
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


@app.route('/')
def home():
    return render_template('index.html')



@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    print(f"Attempting login with username: {username}")  # Debug statement

    user = User.query.filter_by(regd=username).first()
    faculty = Faculty.query.filter_by(email=username).first()

    if user:
        print(f"User found: {user.regd}")  # Debug statement
        if not check_password_hash(user.password, password):
            print("Incorrect password")  # Debug statement
            return jsonify({"message": "Incorrect password"}), 400
        
        session['username'] = username
        session['category'] = 'student'
        session.permanent = True 
        return jsonify({"message": "Login successful", "redirect": "/dashboard"}), 200

    elif faculty:
        print(f"Faculty found: {faculty.email}")  # Debug statement
        if not check_password_hash(faculty.password_hash, password):
            print("Incorrect password")  # Debug statement
            return jsonify({"message": "Incorrect password"}), 400

        session['username'] = username
        session['category'] = faculty.category.lower()  # Store faculty category
        session.permanent = True 
        if faculty.category.lower() == "admin":
            return jsonify({"message": "Login successful", "redirect": "/admin_dashboard"}), 200
        if faculty.category.lower() in ['hod','incharge']:
            return jsonify({"message": "Login successful", "redirect": "/faculty_dashboard"}), 200
        if faculty.category.lower() == "security":
            return jsonify({"message": "Login successful", "redirect": "/scan_qr"}), 200
    print("Username does not exist")  # Debug statement
    return jsonify({"message": "Username does not exist"}), 400


@app.route('/get_session')
def get_session():
    if 'username' in session and 'category' in session:
        return jsonify({
            "username": session['username'],
            "category": session['category']
        }), 200
    else:
        return jsonify({"error": "Session not found"}), 401  # Unauthorized

@app.route('/scan_qr')
@login_required(role='security')  # Allow any authenticated user
def scan_qr():
    if 'username' not in session:
        return redirect(url_for('home'))  # Redirect to home if not logged in
    return render_template('scan_qr.html')  # Render the QR code scanning page


@app.route('/dashboard')
# @no_cache
def dashboard():
    if 'username' not in session or session.get('category') != 'student':
        return redirect(url_for('home'))

    user = User.query.filter_by(regd=session['username']).first()
    if not user:
        return redirect(url_for('home'))

    # Fetch all requests made by the student, sorted by timestamp in descending order (latest first)
    all_requests = PermissionRequest.query.filter_by(student_regd=user.regd).order_by(PermissionRequest.timestamp.desc()).all()

    return render_template('student.html', user=user, all_requests=all_requests)

@app.route('/student_details')
#@login_required(role=['hod', 'incharge'])  # Only HOD and Incharge can access
# @no_cache
def student_details():
    print(f"Session Data: {session}")
    #print("Session Data in /student_details:", session)
    return render_template('student_details.html')




@app.route('/get_students_by_branch', methods=['GET'])
def get_students_by_branch():
    branch = request.args.get('branch')
    print(f"Received branch: {branch}")  # Debug print

    if not branch:
        return jsonify({"success": False, "message": "Branch is required."}), 400

    # Fetch all students in the selected branch
    students = User.query.filter_by(dept=branch).all()
    print(f"Students found: {students}")  # Debug print

    if not students:
        return jsonify({"success": False, "message": "No students found in this branch."}), 404

    # Prepare student data for JSON response
    student_list = []
    for student in students:
        # Count accepted leave requests (Approved with check-out OR Resolved)
        accepted_leave_count = PermissionRequest.query.filter(
            PermissionRequest.student_regd == student.regd,
            PermissionRequest.permission_type == "Leave",
            # Use OR condition for Approved with check-out OR Resolved
            or_(
                and_(PermissionRequest.status == "Approved", PermissionRequest.check_out_time.isnot(None)),
                PermissionRequest.status == "Resolved"
            )
        ).count()

        # Count accepted outing requests (Approved with check-out OR Resolved)
        accepted_outing_count = PermissionRequest.query.filter(
            PermissionRequest.student_regd == student.regd,
            PermissionRequest.permission_type == "Outing",
            # Use OR condition for Approved with check-out OR Resolved
            or_(
                and_(PermissionRequest.status == "Approved", PermissionRequest.check_out_time.isnot(None)),
                PermissionRequest.status == "Resolved"
            )
        ).count()

        student_data = {
            "name": f"{student.first_name} {student.last_name}",
            "regd": student.regd,
            "email": student.email,
            "dept": student.dept,
            "student_phone": student.student_phone,
            "parent_phone": student.parent_phone,
            "accepted_leave_count": accepted_leave_count,  # Updated count
            "accepted_outing_count": accepted_outing_count  # Updated count
        }
        student_list.append(student_data)

    print(f"Student list: {student_list}")  # Debug print
    return jsonify({"success": True, "students": student_list})

@app.route('/faculty_dashboard')
def faculty_dashboard():
    if 'username' not in session or session.get('category') not in ['hod', 'incharge']:
        return redirect(url_for('home'))

    faculty = Faculty.query.filter_by(email=session['username']).first()
    if not faculty:
        return redirect(url_for('home'))

    pending_requests = []
    expired_requests = []

    if faculty.category.lower() == "hod":
        if not faculty.is_active:
            pending_requests = []
        else:
            pending_requests = PermissionRequest.query.filter(
                PermissionRequest.dept == faculty.dept,
                PermissionRequest.hod_status == "Pending",
                # Remove is_processed filter to show all pending HOD actions
            ).all()
    elif faculty.category.lower() == "incharge":
        pending_requests = PermissionRequest.query.filter(
            PermissionRequest.incharge_status == "Pending",
            # Remove is_processed filter to show all pending Incharge actions
        ).all()
        
        # Fetch expired requests for incharge
        ist = timezone('Asia/Kolkata')
        current_time = datetime.now(ist)
        expired_requests = PermissionRequest.query.filter(
            PermissionRequest.status == "Approved",
            PermissionRequest.check_out_time.isnot(None),
            PermissionRequest.check_in_time.is_(None),
            PermissionRequest.is_resolved == False
        ).all()
        
        # Filter out requests that haven't expired yet
        valid_expired_requests = []
        for req in expired_requests:
            if req.permission_type == "Outing":
                end_time = datetime.strptime(f"{req.start_date} {req.end_time}:00", "%Y-%m-%d %H:%M:%S")
            else:  # Leave
                end_time = datetime.strptime(f"{req.end_date} 23:59:59", "%Y-%m-%d %H:%M:%S")
            end_time = ist.localize(end_time)
            if current_time > (end_time + timedelta(minutes=15)):
                valid_expired_requests.append(req)
        expired_requests = valid_expired_requests

    return render_template('faculty.html', 
                         faculty=faculty, 
                         leave_requests=pending_requests,
                         expired_requests=expired_requests)



@app.route('/toggle_status', methods=['POST'])
@login_required(role='hod')
def toggle_status():
    try:
        if 'username' not in session:
            return jsonify({"success": False, "message": "Unauthorized"}), 403
        
        faculty = Faculty.query.filter_by(email=session['username']).first()
        if not faculty or faculty.category.lower() != 'hod':
            return jsonify({"success": False, "message": "Unauthorized"}), 403

        # Toggle the status
        faculty.is_active = not faculty.is_active
        db.session.commit()

        new_status = "Active" if faculty.is_active else "Deactivated"
        return jsonify({"success": True, "new_status": new_status}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": f"Error toggling status: {str(e)}"}), 500


@app.route('/student_dashboard/<regd_no>')
def student_dashboard(regd_no):
    if 'username' not in session or session.get('category') not in ['hod', 'incharge']:
        return redirect(url_for('home'))
    student = User.query.filter_by(regd=regd_no).first()
    if not student:
        return "Student not found", 404
    all_requests = PermissionRequest.query.filter_by(student_regd=student.regd).order_by(PermissionRequest.timestamp.desc()).all()

    return render_template('student.html', user=student, all_requests=all_requests)



@app.route('/admin_dashboard')

@login_required(role='admin')
def admin():
    if 'username' not in session or session.get('category') not in ['admin']:
        return redirect(url_for('home'))

    faculty = Faculty.query.filter_by(email=session['username']).first()
    if not faculty:
        return redirect(url_for('home'))
    return render_template("admin.html")


@app.route('/new_password')
def new_password():
    if 'username' not in session:
        return redirect(url_for('home'))  # Redirect if not logged in
    return render_template('newpassword.html')



@app.route('/send_otp', methods=['POST'])
def send_otp():
    data = request.get_json()
    email = data.get("email")

    # Check if the user exists
    user = User.query.filter_by(email=email).first()
    faculty = Faculty.query.filter_by(email=email).first()

    if not user and not faculty:
        return jsonify({"message": "Email not registered!"}), 400

    # Generate a 6-digit OTP
    otp = str(random.randint(100000, 999999))
    session["otp"] = otp  # Store OTP in session
    session["reset_email"] = email  # Store email
    session["otp_expiry"] = (datetime.utcnow() + timedelta(minutes=2)).strftime("%Y-%m-%d %H:%M:%S")

    # Send OTP via email
    msg = Message("Password Reset OTP", sender="pragadapre143@gmail.com", recipients=[email])
    msg.body = f"Your OTP for password reset is: {otp}. This OTP is valid for 2 minutes."
    mail.send(msg)

    return jsonify({"message": "OTP sent successfully!"}), 200




@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    entered_otp = data.get("otp")
    new_password = data.get("new_password")

    # Check if OTP exists and is not expired
    otp_expiry = session.get("otp_expiry")
    if not otp_expiry or datetime.utcnow() > datetime.strptime(otp_expiry, "%Y-%m-%d %H:%M:%S"):
        return jsonify({"message": "OTP expired! Request a new one."}), 400

    # Check OTP
    if session.get("otp") != entered_otp:
        return jsonify({"message": "Invalid OTP!"}), 400

    email = session.get("reset_email")

    # Update password
    user = User.query.filter_by(email=email).first()
    faculty = Faculty.query.filter_by(email=email).first()

    if user:
        user.password = generate_password_hash(new_password)
    elif faculty:
        faculty.password_hash = generate_password_hash(new_password)

    db.session.commit()

    # Clear session OTP
    session.pop("otp", None)
    session.pop("reset_email", None)
    session.pop("otp_expiry", None)

    return jsonify({"message": "Password updated successfully!"}), 200



@app.route('/submit_permission', methods=['POST'])
def submit_permission():
    if 'username' not in session or session.get('category') != 'student':
        return jsonify({"message": "Unauthorized"}), 403

    user = User.query.filter_by(regd=session['username']).first()
    if not user:
        return jsonify({"message": "User not found"}), 404

    data = request.form.to_dict()
    permission_type = data.get('permission_type')

    # Handle letter image upload - compulsory for female students
    letter_image_path = None
    if user.gender.lower() == 'female':
        if 'letter_image' not in request.files or not request.files['letter_image'].filename:
            return jsonify({"message": "Letter upload is compulsory for female students."}), 400
        file = request.files['letter_image']
        if file and allowed_file(file.filename, {'png', 'jpg', 'jpeg'}):
            filename = secure_filename(f"{user.regd}_{permission_type}_{datetime.now(ist).strftime('%Y%m%d_%H%M%S')}.{file.filename.rsplit('.', 1)[1].lower()}")
            letter_image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(letter_image_path)
            letter_image_path = f"static/uploads/{filename}"
        else:
            return jsonify({"message": "Invalid file type. Only PNG, JPG, or JPEG files are allowed."}), 400
    # For non-female students, letter upload remains optional (no change needed here)

    try:
        new_request = PermissionRequest(
            student_regd=user.regd,
            student_name=f"{user.first_name} {user.last_name}",
            student_email=user.email,
            dept=user.dept,
            permission_type=permission_type,
            start_time=data.get('start_time'),
            end_time=data.get('end_time'),
            start_date=data.get('start_date') or data.get('outing_start_date'),
            end_date=data.get('end_date'),
            reason=data.get('reason'),
            status="Pending",
            hod_status="NIL" if permission_type == "Outing" else "Pending",
            incharge_status="Pending",
            timestamp=datetime.now(ist),
            letter_path=letter_image_path
        )

        # Outing HOD approval logic
        if permission_type == "Outing":
            outing_date = datetime.strptime(data.get('start_date'), '%Y-%m-%d').date()
            start_time = datetime.strptime(data.get('start_time'), '%H:%M').time()
            end_time = datetime.strptime(data.get('end_time'), '%H:%M').time()
            if outing_date.weekday() <= 5 and start_time >= time(8, 30) and end_time <= time(16, 30):
                new_request.hod_status = "Pending"

        db.session.add(new_request)
        db.session.commit()

        # Send emails (unchanged logic, included for completeness)
        if permission_type == "Leave":
            hod = Faculty.query.filter_by(dept=user.dept, category="HOD").first()
            incharge = Faculty.query.filter_by(category="Incharge").first()
            if hod:
                msg = Message("New Leave Request - HOD", sender="pragadaprem143@gmail.com", recipients=[hod.email])
                msg.body = f"""
                Dear {incharge.first_name},

                 A new leave request has been submitted by {user.first_name} {user.last_name}.

                 🏫 Department: {user.dept}
                 📌 Student: {user.first_name} {user.last_name} ({user.regd})
                 📩 Email: {user.email}
                 📞 Phone: {user.student_phone}
                 Start Date: {data.get('start_date') or 'N/A'}
                 End Date: {data.get('end_date') or 'N/A'}
                 Reason: {data.get('reason')}

                 Please log in to the faculty dashboard to review and take action on this request.

                 Best Regards,
                 Admin
                """
                mail.send(msg)
            if incharge:
                msg = Message("New Leave Request - Incharge", sender="pragadaprem143@gmail.com", recipients=[incharge.email])
                msg.body = f"""
                Dear {incharge.first_name},

                 A new leave request has been submitted by {user.first_name} {user.last_name}.

                 🏫 Department: {user.dept}
                 📌 Student: {user.first_name} {user.last_name} ({user.regd})
                 📩 Email: {user.email}
                 📞 Phone: {user.student_phone}
                 Start Date: {data.get('start_date') or 'N/A'}
                 End Date: {data.get('end_date') or 'N/A'}
                 Reason: {data.get('reason')}

                 

                {'Letter: ' + url_for('static', filename=new_request.letter_path.split('/', 1)[1], _external=True) if new_request.letter_path else ''}
                Please log in to the faculty dashboard to review and take action on this request.

                 Best Regards,
                 Admin
                """
                mail.send(msg)
        elif permission_type == "Outing":
            incharge = Faculty.query.filter_by(category="Incharge").first()
            hod = Faculty.query.filter_by(dept=user.dept, category="HOD").first()
            if incharge:
                msg = Message("New Outing Request - Incharge", sender="pragadaprem143@gmail.com", recipients=[incharge.email])
                msg.body = f"""
                Dear {incharge.first_name},

                 A new leave request has been submitted by {user.first_name} {user.last_name}.

                 🏫 Department: {user.dept}
                 📌 Student: {user.first_name} {user.last_name} ({user.regd})
                 📩 Email: {user.email}
                 📞 Phone: {user.student_phone}
                 Date: {data.get('start_date') or 'N/A'}
                 Start Time: {data.get('start_time') or 'N/A'}
                 End Time: {data.get('end_time') or 'N/A'}
                 Reason: {data.get('reason')}

                 

                {'Letter: ' + url_for('static', filename=new_request.letter_path.split('/', 1)[1], _external=True) if new_request.letter_path else ''}
                Please log in to the faculty dashboard to review and take action on this request.

                 Best Regards,
                 Admin
                """
                mail.send(msg)
            if new_request.hod_status == "Pending" and hod:
                msg = Message("New Outing Request - HOD", sender="pragadaprem143@gmail.com", recipients=[hod.email])
                msg.body = f"""
                Dear {incharge.first_name},

                 A new leave request has been submitted by {user.first_name} {user.last_name}.

                 🏫 Department: {user.dept}
                 📌 Student: {user.first_name} {user.last_name} ({user.regd})
                 📩 Email: {user.email}
                 📞 Phone: {user.student_phone}
                 Date: {data.get('start_date') or 'N/A'}
                 Start Time: {data.get('start_time') or 'N/A'}
                 End Time: {data.get('end_time') or 'N/A'}
                 Reason: {data.get('reason')}

                 

                {'Letter: ' + url_for('static', filename=new_request.letter_path.split('/', 1)[1], _external=True) if new_request.letter_path else ''}
                Please log in to the faculty dashboard to review and take action on this request.

                 Best Regards,
                 Admin
                """
                mail.send(msg)

        return jsonify({"message": "Permission request submitted successfully!"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"message": f"Database error: {str(e)}"}), 500

def allowed_file(filename, allowed_extensions={'png', 'jpg', 'jpeg'}):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions






def send_sms_fast2sms(phone_number, message):
    url = "https://www.fast2sms.com/dev/bulkV2"
    headers = {
        "authorization": os.getenv("FAST2SMS_API_KEY"),  # Store API Key in environment variable
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {
        "route": "q",
        "message": message,
        "language": "english",
        "flash": 0,
        "numbers": phone_number
    }
    response = requests.post(url, headers=headers, data=data)
    return response.json()



@app.route('/process_request', methods=['POST'])
def process_request_post():
    try:
        if 'username' not in session:
            return jsonify({"success": False, "message": "Unauthorized access"}), 403
        
        data = request.get_json()
        request_id = data.get("request_id")
        action = data.get("action")
        role = data.get("role")
        message = data.get("message", "")
        approver_email = session['username']

        faculty = Faculty.query.filter_by(email=approver_email).first()
        if not faculty:
            return jsonify({"success": False, "message": "Unauthorized access"}), 403

        permission_request = PermissionRequest.query.get(request_id)
        if not permission_request:
            return jsonify({"success": False, "message": "Request not found"}), 404

        hod = Faculty.query.filter_by(dept=permission_request.dept, category="HOD").first()
        hod_deactivated = hod and not hod.is_active

        # Process approval/rejection without setting is_processed immediately
        if role == "incharge" and faculty.category.lower() == "incharge":
            permission_request.incharge_status = "Approved" if action == "approve" else "Rejected"
            if action == "reject":
                permission_request.incharge_message = message
        elif role == "hod" and faculty.category.lower() == "hod":
            if permission_request.permission_type in ["Leave", "Outing"]:
                permission_request.hod_status = "Approved" if action == "approve" else "Rejected"
                if action == "reject":
                    permission_request.hod_message = message
        else:
            return jsonify({"success": False, "message": "Unauthorized access"}), 403

        # Final status check and set is_processed only when fully resolved
        if permission_request.permission_type == "Leave":
            if hod_deactivated:
                permission_request.status = permission_request.incharge_status
                permission_request.is_processed = True
            else:
                if permission_request.hod_status == "Rejected" or permission_request.incharge_status == "Rejected":
                    permission_request.status = "Rejected"
                    permission_request.is_processed = True
                elif permission_request.hod_status == "Approved" and permission_request.incharge_status == "Approved":
                    permission_request.status = "Approved"
                    permission_request.is_processed = True
        elif permission_request.permission_type == "Outing":
            if hod_deactivated or permission_request.hod_status == "NIL":
                permission_request.status = permission_request.incharge_status
                permission_request.is_processed = True
            else:
                if permission_request.hod_status == "Rejected" or permission_request.incharge_status == "Rejected":
                    permission_request.status = "Rejected"
                    permission_request.is_processed = True
                elif permission_request.hod_status == "Approved" and permission_request.incharge_status == "Approved":
                    permission_request.status = "Approved"
                    permission_request.is_processed = True

        db.session.commit()

        if permission_request.status == "Approved":
            # QR code generation
            qr_data = {
                "student_name": permission_request.student_name,
                "student_regd": permission_request.student_regd,
                "dept": permission_request.dept,
                "permission_type": permission_request.permission_type,
                "status": permission_request.status,
                "start_time": permission_request.start_time,
                "end_time": permission_request.end_time,
                "start_date": permission_request.start_date,
                "end_date": permission_request.end_date,
                "Reason": permission_request.reason,
                "id": permission_request.id
            }
            qr_data_json = json.dumps(qr_data)
            encrypted_data = cipher_suite.encrypt(qr_data_json.encode())
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(encrypted_data)
            qr.make(fit=True)
            img = qr.make_image(fill='black', back_color='white')
            qr_filename = f"qr_{permission_request.student_regd}.png"
            qr_path = os.path.join(app.config['UPLOAD_FOLDER'], qr_filename)
            img.save(qr_path)
            qr_url = url_for('static', filename=f'uploads/{qr_filename}', _external=True)

            email_subject = f"Your {permission_request.permission_type} request has been {permission_request.status}"
            email_body = f"""
            Dear Student,
            Your {permission_request.permission_type} request has been {permission_request.status}.
            Please find the QR code for verification at: {qr_url}
            Best Regards,
            Admin
            """
            msg = Message(email_subject, sender="pragadaprem143@gmail.com", recipients=[permission_request.student_email])
            msg.body = email_body
            mail.send(msg)

        return jsonify({
            "success": True,
            "new_status": permission_request.status,
            "hod_status": permission_request.hod_status,
            "incharge_status": permission_request.incharge_status
        }), 200

    except Exception as e:
        return jsonify({"success": False, "message": f"Error processing request: {str(e)}"}), 500



@app.route('/decrypt_qr_data', methods=['POST'])
def decrypt_qr_data():
    try:
        data = request.get_json()
        encrypted_data = data.get('encrypted_data')

        if not encrypted_data:
            return jsonify({"success": False, "message": "No encrypted data provided."}), 400

        # Decrypt the data
        decrypted_data = cipher_suite.decrypt(encrypted_data.encode()).decode()
        qr_data = json.loads(decrypted_data)

        # Validate expiration
        permission_id = qr_data.get('id')
        permission = PermissionRequest.query.get(permission_id)
        if not permission or permission.status != "Approved":
            return jsonify({"success": False, "message": "Invalid or unapproved permission."}), 400

        ist = timezone('Asia/Kolkata')
        current_time = datetime.now(ist)
        if permission.permission_type == "Outing":
            end_datetime = ist.localize(datetime.strptime(
                f"{permission.start_date} {permission.end_time}:00", "%Y-%m-%d %H:%M:%S"))
        else:  # Leave
            end_datetime = ist.localize(datetime.strptime(
                f"{permission.end_date} 23:59:59", "%Y-%m-%d %H:%M:%S"))
        grace_period = timedelta(minutes=15)

        if current_time > (end_datetime + grace_period):
            return jsonify({"success": False, "message": "QR code has expired."}), 400

        return jsonify({"success": True, "decrypted_data": decrypted_data}), 200

    except Exception as e:
        return jsonify({"success": False, "message": f"Error decrypting data: {str(e)}"}), 500

def delete_expired_qr_codes():
    print("Running delete_expired_qr_codes job...")
    with app.app_context():
        # Get the current time in IST (Indian Standard Time)
        ist = timezone('Asia/Kolkata')
        current_time = datetime.now(ist)

        # Fetch all approved requests
        expired_requests = PermissionRequest.query.filter(
            PermissionRequest.status == "Approved"
        ).all()

        for request in expired_requests:
            # Handle Outing Requests (only end_time is provided)
            if request.permission_type == "Outing":
                if request.end_time is None:
                    print(f"Skipping outing request ID {request.id} because end_time is None.")
                    continue

                # For outings, use today's date and the provided end_time
                end_date = current_time.strftime("%Y-%m-%d")  # Today's date
                end_time = request.end_time

                # Handle cases where end_time does not include seconds
                if len(end_time.split(':')) == 2:  # Only hours and minutes are provided
                    end_time += ":00"  # Add seconds

                # Combine end_date and end_time into a datetime object
                end_datetime_str = f"{end_date} {end_time}"
                end_datetime = datetime.strptime(end_datetime_str, "%Y-%m-%d %H:%M:%S")
                end_datetime = ist.localize(end_datetime)

                # Add a grace period of 15 minutes to the end time
                grace_period = timedelta(minutes=15)
                end_datetime_with_grace = end_datetime + grace_period

            # Handle Leave Requests (only end_date is provided)
            elif request.permission_type == "Leave":
                if request.end_date is None:
                    print(f"Skipping leave request ID {request.id} because end_date is None.")
                    continue

                # For leaves, use the provided end_date and a default end_time (end of day)
                end_date = request.end_date
                end_time = "23:59:59"  # Default end_time for leave requests

                # Combine end_date and end_time into a datetime object
                end_datetime_str = f"{end_date} {end_time}"
                end_datetime = datetime.strptime(end_datetime_str, "%Y-%m-%d %H:%M:%S")
                end_datetime = ist.localize(end_datetime)

                # No grace period for leave requests
                end_datetime_with_grace = end_datetime

            else:
                print(f"Skipping request ID {request.id} because permission_type is invalid.")
                continue

            # Check if the request has expired (including grace period)
            if current_time > end_datetime_with_grace:
                # Generate the QR code filename
                qr_filename = f"qr_{request.student_regd}.png"
                qr_path = os.path.join(app.config['UPLOAD_FOLDER'], qr_filename)

                # Check if the QR code file exists and delete it
                print(f"Checking QR code at path: {qr_path}")
                if os.path.exists(qr_path):
                    os.remove(qr_path)
                    print(f"Deleted QR code for request ID: {request.id}")
                else:
                    print(f"QR code not found at path: {qr_path}")



def send_email(subject, body, recipient):
    try:
        msg = Message(subject, sender="pragadaprem143@gmail.com", recipients=[recipient])
        msg.body = body
        mail.send(msg)
        print(f"Email sent successfully to {recipient}")
    except Exception as e:
        print(f"Failed to send email to {recipient}: {str(e)}")
        traceback.print_exc()  # Print the full traceback


def check_expired_permissions_and_notify():
    with app.app_context():
        try:
            ist = timezone('Asia/Kolkata')
            current_time = datetime.now(ist)
            
            # Fetch all approved, unresolved requests where check-out has happened and notification not sent
            expired_requests = PermissionRequest.query.filter(
                PermissionRequest.status == "Approved",
                PermissionRequest.is_processed == True,
                PermissionRequest.is_resolved == False,
                PermissionRequest.check_out_time.isnot(None),
                PermissionRequest.notification_sent == False
            ).all()

            for request in expired_requests:
                # Calculate expiration time based on permission type
                if request.permission_type == "Outing":
                    end_datetime_str = f"{request.start_date} {request.end_time}:00"
                    end_datetime = ist.localize(datetime.strptime(end_datetime_str, "%Y-%m-%d %H:%M:%S"))
                elif request.permission_type == "Leave":
                    end_datetime_str = f"{request.end_date} 23:59:59"
                    end_datetime = ist.localize(datetime.strptime(end_datetime_str, "%Y-%m-%d %H:%M:%S"))
                else:
                    continue

                grace_period = timedelta(minutes=15)
                expiration_time = end_datetime + grace_period

                # Check if expired and student hasn't checked in
                if current_time > expiration_time and not request.check_in_time and request.check_out_time:
                    # Fetch student details to get phone numbers
                    student = User.query.filter_by(regd=request.student_regd).first()
                    if not student:
                        print(f"Student with regd {request.student_regd} not found.")
                        continue

                    # Fetch Incharge and HOD
                    incharge = Faculty.query.filter_by(category="Incharge").first()
                    hod = Faculty.query.filter_by(dept=request.dept, category="HOD").first()

                    # Common details for notifications
                    expiration_str = expiration_time.strftime('%Y-%m-%d %H:%M:%S')
                    checkout_str = request.check_out_time.strftime('%Y-%m-%d %H:%M:%S')

                    # Check if Outing is during working hours (Monday-Saturday, 8:30 AM - 4:30 PM)
                    outing_date = datetime.strptime(request.start_date, "%Y-%m-%d").date()
                    start_time = datetime.strptime(request.start_time, "%H:%M").time()
                    end_time = datetime.strptime(request.end_time, "%H:%M").time()
                    is_working_hours = (outing_date.weekday() <= 5 and 
                                       start_time >= time(8, 30) and 
                                       end_time <= time(16, 30))

                    # Notify Incharge (always notified)
                    if incharge:
                        subject = f"Student {request.student_name} Failed to Check-in After Expiration"
                        body = f"""
                        Dear {incharge.first_name},
                        
                        Student Details:
                        Name: {request.student_name}
                        Regd: {request.student_regd}
                        Type: {request.permission_type}
                        Expired: {expiration_str}
                        Check-out: {checkout_str}
                        Student Phone: {student.student_phone}
                        Parent Phone: {student.parent_phone}
                        
                        The student has not checked in after their permission expired.
                        Please consult with the student and resolve this issue from your dashboard.
                        """
                        send_email(subject, body, incharge.email)

                    # Notify HOD if:
                    # 1. Permission is a Leave request, OR
                    # 2. Permission is an Outing during working hours AND HOD is active
                    if hod and hod.is_active:
                        should_notify_hod = (
                            request.permission_type == "Leave" or
                            (request.permission_type == "Outing" and is_working_hours)
                        )
                        if should_notify_hod:
                            subject = f"Student {request.student_name} Failed to Check-in After Expiration"
                            body = f"""
                            Dear {hod.first_name},
                            
                            Student Details:
                            Name: {request.student_name}
                            Regd: {request.student_regd}
                            Type: {request.permission_type}
                            Expired: {expiration_str}
                            Check-out: {checkout_str}
                            Student Phone: {student.student_phone}
                            Parent Phone: {student.parent_phone}
                            
                            The student has not checked in after their permission expired.
                            Please review this issue as necessary.
                            """
                            send_email(subject, body, hod.email)

                    # Notify the student (unchanged)
                    student_subject = "Action Required: Late Return Notification"
                    student_body = f"""
                    Dear {request.student_name},
                    
                    Your {request.permission_type} permission expired at {expiration_str}.
                    You have not checked in yet. Please report to the incharge immediately.
                    Your QR code is now invalid.
                    """
                    send_email(student_subject, student_body, request.student_email)

                    # Mark notification as sent
                    request.notification_sent = True
                    db.session.commit()

        except Exception as e:
            print(f"Error in check_expired_permissions: {str(e)}")
            traceback.print_exc()


            

@app.route('/check_in', methods=['POST'])
def check_in():
    try:
        data = request.get_json()
        student_regd = data.get("student_regd")
        permission_id = data.get("permission_id")

        # Fetch the permission request
        permission_request = PermissionRequest.query.filter_by(
            student_regd=student_regd,
            id=permission_id,
            status="Approved"
        ).first()

        if not permission_request:
            return jsonify({"success": False, "message": "Permission request not found or not approved."}), 404

        ist = timezone('Asia/Kolkata')
        current_time = datetime.now(ist)

        # Calculate expiration time based on permission type
        if permission_request.permission_type == "Outing":
            end_datetime = ist.localize(datetime.strptime(
                f"{permission_request.start_date} {permission_request.end_time}:00", 
                "%Y-%m-%d %H:%M:%S"
            ))
        else:  # Leave
            end_datetime = ist.localize(datetime.strptime(
                f"{permission_request.end_date} 23:59:59", 
                "%Y-%m-%d %H:%M:%S"
            ))

        grace_period = timedelta(minutes=15)
        expiration_time = end_datetime + grace_period

        # Check if the QR code has expired
        if current_time > expiration_time:
            return jsonify({"success": False, "message": "QR code expired/time aypoyindi. Please consult the incharge."}), 400

        # If not expired, proceed with check-in
        permission_request.check_in_time = current_time
        db.session.commit()

        return jsonify({"success": True, "message": "Check-in successful."}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": f"Error during check-in: {str(e)}"}), 500

@app.route('/check_out', methods=['POST'])
def check_out():
    try:
        data = request.get_json()
        print("Received data for check-out:", data)  # Debug statement

        if not data:
            return jsonify({"success": False, "message": "No data provided in the request."}), 400

        student_regd = data.get("student_regd")
        permission_id = data.get("permission_id")

        if not student_regd or not permission_id:
            return jsonify({"success": False, "message": "Student registration number and permission ID are required."}), 400

        # Fetch the permission request
        permission_request = PermissionRequest.query.filter_by(
            student_regd=student_regd,
            id=permission_id,
            status="Approved"
        ).first()

        if not permission_request:
            return jsonify({"success": False, "message": "Permission request not found or not approved."}), 404

        # Get the current time in IST
        ist = timezone('Asia/Kolkata')
        current_time = datetime.now(ist)

        # Handle Outing and Leave requests differently
        if permission_request.permission_type == "Outing":
            # For Outing, use the same date for start and end, with start_time and end_time
            start_date = permission_request.start_date
            end_date = permission_request.start_date  # Same day for Outing
            start_time = permission_request.start_time or "00:00"  # Default if None
            end_time = permission_request.end_time or "23:59"    # Default if None

            # Ensure time format includes seconds
            start_time_str = f"{start_date} {start_time}"
            end_time_str = f"{end_date} {end_time}"
            if len(start_time.split(':')) == 2:
                start_time_str += ":00"
            if len(end_time.split(':')) == 2:
                end_time_str += ":00"

        elif permission_request.permission_type == "Leave":
            # For Leave, use start_date and end_date, with default times if start_time/end_time are None
            start_date = permission_request.start_date
            end_date = permission_request.end_date
            start_time = permission_request.start_time or "00:00"  # Start of day if None
            end_time = permission_request.end_time or "23:59"      # End of day if None

            # Ensure time format includes seconds
            start_time_str = f"{start_date} {start_time}"
            end_time_str = f"{end_date} {end_time}"
            if len(start_time.split(':')) == 2:
                start_time_str += ":00"
            if len(end_time.split(':')) == 2:
                end_time_str += ":00"

        else:
            return jsonify({"success": False, "message": "Invalid permission type."}), 400

        # Convert to datetime objects
        start_datetime = ist.localize(datetime.strptime(start_time_str, "%Y-%m-%d %H:%M:%S"))
        end_datetime = ist.localize(datetime.strptime(end_time_str, "%Y-%m-%d %H:%M:%S"))

        # Check if current time is within the permission range
        if current_time < start_datetime or current_time > end_datetime:
            return jsonify({"success": False, "message": "Check-out is only allowed within the permission request's time range."}), 400

        # Update check-out time
        permission_request.check_out_time = current_time
        db.session.commit()

        print(f"Check-out successful for permission ID: {permission_id}")  # Debug statement
        return jsonify({"success": True, "message": "Check-out successful."}), 200

    except Exception as e:
        db.session.rollback()
        print(f"Error during check-out: {str(e)}")  # Debug statement
        return jsonify({"success": False, "message": f"Error during check-out: {str(e)}"}), 500




@app.route('/logout')
def logout():
    session.clear()  # Clear session
    response = redirect(url_for('home'))

    # Prevent caching to block back navigation
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"

    return response




@app.route('/form')
def form():
    return render_template('frm.html')

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403  # Create a 403.html template for unauthorized access


@app.route('/get_student_details', methods=['POST'])
def get_student_details():
    if 'username' not in session:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.get_json()
    student_regd = data.get("student_regd")

    # Ensure the student can only fetch their own details
    if session['category'] == 'student' and student_regd != session['username']:
        return jsonify({"success": False, "message": "You can only access your own details"}), 403

    student = User.query.filter_by(regd=student_regd).first()
    if not student:
        return jsonify({"success": False, "message": "Student not found"}), 404

    student_data = {
        "name": f"{student.first_name} {student.last_name}",
        "register_number": student.regd,
        "department": student.dept,
        "phone": student.student_phone,
        "email": student.email,
        "gender": student.gender,  # Include gender for the form
        "photo": student.photo,
        "leave_requests": PermissionRequest.query.filter(
            PermissionRequest.student_regd == student_regd,
            PermissionRequest.permission_type == "Leave",
            PermissionRequest.status == "Approved",
            PermissionRequest.check_out_time.isnot(None)
        ).count(),

        # Count accepted outing requests where check_out_time is not null
        "outing_requests" : PermissionRequest.query.filter(
            PermissionRequest.student_regd == student_regd,
            PermissionRequest.permission_type == "Outing",
            PermissionRequest.status == "Approved",
            PermissionRequest.check_out_time.isnot(None)
        ).count(),
        "resolved_requests": PermissionRequest.query.filter(
            PermissionRequest.student_regd == student_regd,
            PermissionRequest.status == "Resolved"
        ).count()
    }
    return jsonify({"success": True, "student": student_data})

def reset_permissions_db():
    with app.app_context():
        # Calculate the timestamp for 6 months ago
        six_months_ago = datetime.now(timezone.utc) - timedelta(days = 180)
        # Query and delete old permission requests
        old_requests = PermissionRequest.query.filter(
            PermissionRequest.timestamp < six_months_ago
        ).all()

        for request in old_requests:
            db.session.delete(request)

        db.session.commit()
        print("✅ Old permission requests (older than 6 months) deleted successfully.")


@app.route('/addStudent')
@login_required(role='admin')  # Only admin can access
def addStudent():
    print(f"Session: {session}")
    return render_template('add_student.html')

@app.route('/removeStudent')
@login_required(role='admin')  # Only admin can access
def removeStudent():
    return render_template('remove_student.html')

@app.route('/modifyStudent')
@login_required(role='admin')  # Only admin can access
def modifyStudent():
    return render_template('modify_student.html')

@app.route('/viewStudent')
@login_required(role='admin')  # Only admin can access
def viewStudent():
    return render_template('view_student_details.html')

@app.route('/monitorStudent')
@login_required(role='admin') # Only admin
def monitorStudent():
    return render_template('monitor.html')

@app.route('/admin/get_students_checked_out', methods=['GET'])
def get_students_checked_out():
    try:
        department = request.args.get('department')
        
        if not department or department == "NONE":
            return jsonify({"success": False, "message": "Please select a valid department."}), 400

        print(f"Fetching checked-out students for department: {department}")  # Debug

        # Fetch permission requests where students have checked out
        checked_out_requests = PermissionRequest.query.filter(
            PermissionRequest.check_out_time.isnot(None),  # Only students who have checked out
            PermissionRequest.dept == department  # Filter by department
        ).all()

        print(f"Total checked-out requests: {len(checked_out_requests)}")  # Debug

        if not checked_out_requests:
            return jsonify({"success": False, "message": "No students found who have checked out."}), 404

        # Group requests by student and keep only the latest check-out for each student
        latest_requests = {}
        for prequest in checked_out_requests:
            if prequest.student_regd not in latest_requests:
                latest_requests[prequest.student_regd] = prequest
            else:
                # Compare check-out times and keep the latest one
                if prequest.check_out_time > latest_requests[prequest.student_regd].check_out_time:
                    latest_requests[prequest.student_regd] = prequest

        # Prepare the data to be returned
        students_data = []
        for student_regd, prequest in latest_requests.items():
            # Fetch the corresponding student from the User table
            student = User.query.filter_by(regd=student_regd).first()
            if student:
                print(f"Found student: {student.regd} ({student.first_name} {student.last_name})")  # Debug
                students_data.append({
                    "regd": student.regd,
                    "first_name": student.first_name,
                    "last_name": student.last_name,
                    "email": student.email,
                    "student_phone": student.student_phone,
                    "parent_phone": student.parent_phone,
                    "dept": student.dept,
                    "photo": student.photo,
                    "permission_type": prequest.permission_type,
                    "start_time": prequest.start_time,
                    "end_time": prequest.end_time,
                    "start_date": prequest.start_date,
                    "end_date": prequest.end_date,
                    "check_in_time": prequest.check_in_time.strftime("%Y-%m-%d %H:%M:%S") if prequest.check_in_time else None,
                    "check_out_time": prequest.check_out_time.strftime("%Y-%m-%d %H:%M:%S") if prequest.check_out_time else None,
                    "reason": prequest.reason
                })

        if not students_data:
            print(f"No students found in the {department} department who have checked out.")  # Debug
            return jsonify({"success": False, "message": f"No students found in the {department} department who have checked out."}), 404

        print(f"Returning data for {len(students_data)} students.")  # Debug
        return jsonify({"success": True, "students": students_data})

    except Exception as e:
        print(f"Error in get_students_checked_out: {str(e)}")  # Debug
        return jsonify({"success": False, "message": str(e)}), 500  

@app.route('/resolve_permission', methods=['POST'])
def resolve_permission():
    try:
        data = request.get_json()
        student_regd = data.get('student_regd')
        permission_id = data.get('permission_id')

        if not student_regd or not permission_id:
            return jsonify({"success": False, "message": "Student registration number and permission ID are required."}), 400

        # Fetch the permission request
        permission_request = PermissionRequest.query.filter_by(
            student_regd=student_regd,
            id=permission_id
        ).first()

        if not permission_request:
            return jsonify({"success": False, "message": "Permission request not found."}), 404

        # Update the status and check-in time
        permission_request.status = "Resolved"
        permission_request.check_in_time = datetime.now(timezone('Asia/Kolkata'))
        db.session.commit()

        return jsonify({"success": True, "message": "Permission request resolved successfully."}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": f"Error resolving permission: {str(e)}"}), 500


@app.route('/addFaculty')
@login_required(role='admin')  # Only admin can access
def addFaculty():
    return render_template('add_faculty.html')

@app.route('/removeFaculty')
@login_required(role='admin')  # Only admin can access
def removeFaculty():
    return render_template('remove_faculty.html')

@app.route('/modifyFaculty')
@login_required(role='admin')  # Only admin can access
def modifyFaculty():
    return render_template('modify_faculty.html')

@app.route('/viewFaculty')
@login_required(role='admin')  # Only admin can access
def viewFaculty():
    return render_template('view_faculty_details.html')


# @app.route('/upload1', methods=['POST'])
# def upload1():
#     if 'file' not in request.files:
#         flash('No file selected', 'error')
#         return redirect(request.url)
    
#     file = request.files['file']
#     if file.filename == '' or not allowed_file(file.filename, CSV_EXTENSIONS):
#         flash('Invalid file type. Only CSV files are allowed.', 'error')
#         return redirect(request.url)
    
#     filename = secure_filename(file.filename)
#     filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
#     file.save(filepath)
    
#     try:
#         with open(filepath, 'r') as csvfile:
#             reader = csv.DictReader(csvfile)
#             for row in reader:
#                 if not any(row.values()):
#                     continue
                
#                 row = {k.strip(): v.strip() if isinstance(v, str) else v for k, v in row.items()}
#                 required_fields = ['regd', 'first_name', 'email']
#                 if not all(row.get(field) for field in required_fields):
#                     flash(f"Missing required fields in row: {row}", 'error')
#                     continue
                
#                 existing_user = User.query.filter_by(regd=row['regd']).first()
#                 if existing_user:
#                     flash(f"Student with regd {row['regd']} already exists", 'warning')
#                     continue
                
#                 # Verify photo exists
#                 photo_filename = row['photo']
#                 photo_path = os.path.join(app.config['UPLOAD_FOLDER'], photo_filename)
#                 if not os.path.exists(photo_path):
#                     flash(f"Photo {photo_filename} not found for regd {row['regd']}", 'warning')
#                     photo_db_path = None
#                 else:
#                     photo_db_path = photo_filename
                
#                 hashed_password = generate_password_hash(row['password'])
#                 new_user = User(
#                     regd=row['regd'],
#                     first_name=row['first_name'],
#                     last_name=row['last_name'],
#                     gender=row.get('gender', 'not prefer to say'),
#                     email=row['email'],
#                     dept=row['dept'],
#                     student_phone=row['student_phone'],
#                     parent_phone=row['parent_phone'],
#                     address=row['address'],
#                     password=hashed_password,
#                     photo=photo_db_path,
#                     category=row['category']
#                 )
#                 db.session.add(new_user)
#             db.session.commit()
        
#         flash('CSV file processed successfully', 'success')
#     except Exception as e:
#         db.session.rollback()
#         flash(f'Error processing CSV: {str(e)}', 'error')
#     finally:
#         os.remove(filepath)
    
#     return redirect(url_for('addStudent'))

import zipfile
import os
import shutil

import zipfile
import os
import shutil

@app.route('/upload1', methods=['POST'])
def upload1():
    if 'file' not in request.files:
        flash('No file selected', 'error')
        return redirect(request.url)
    
    file = request.files['file']
    if file.filename == '' or not file.filename.endswith('.zip'):
        flash('Please upload a valid ZIP file', 'error')
        return redirect(request.url)
    
    zip_filename = secure_filename(file.filename)
    zip_filepath = os.path.join(app.config['UPLOAD_FOLDER'], zip_filename)
    file.save(zip_filepath)
    
    photo_target_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'students')
    if not os.path.exists(photo_target_dir):
        os.makedirs(photo_target_dir)
    
    try:
        temp_extract_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'temp_extract')
        if os.path.exists(temp_extract_dir):
            shutil.rmtree(temp_extract_dir)
        os.makedirs(temp_extract_dir)
        
        with zipfile.ZipFile(zip_filepath, 'r') as zip_ref:
            zip_ref.extractall(temp_extract_dir)
        
        csv_file = None
        for root, dirs, files in os.walk(temp_extract_dir):
            for file in files:
                if file.endswith('.csv'):
                    csv_file = os.path.join(root, file)
                    break
            if csv_file:
                break
        
        if not csv_file:
            flash('No CSV file found in ZIP', 'error')
            return redirect(url_for('addStudent'))
        
        with open(csv_file, 'r') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                if not any(row.values()):
                    continue
                
                row = {k.strip(): v.strip() if isinstance(v, str) else v for k, v in row.items()}
                required_fields = ['regd', 'first_name', 'email']
                if not all(row.get(field) for field in required_fields):
                    flash(f"Missing required fields in row: {row}", 'error')
                    continue
                
                existing_user = User.query.filter_by(regd=row['regd']).first()
                if existing_user:
                    flash(f"Student with regd {row['regd']} already exists", 'warning')
                    continue
                
                photo_filename = row['photo']
                photo_source_path = os.path.join(os.path.dirname(csv_file), photo_filename)
                if not os.path.exists(photo_source_path):
                    flash(f"Photo {photo_filename} not found in ZIP for regd {row['regd']}", 'warning')
                    photo_db_path = None
                else:
                    photo_target_path = os.path.join(photo_target_dir, photo_filename)
                    if os.path.exists(photo_target_path):
                        os.remove(photo_target_path)
                    shutil.move(photo_source_path, photo_target_path)
                    # Use forward slashes for the database path
                    photo_db_path = f"students/{photo_filename}"
                
                hashed_password = generate_password_hash(row['password'])
                new_user = User(
                    regd=row['regd'],
                    first_name=row['first_name'],
                    last_name=row['last_name'],
                    gender=row.get('gender', 'not prefer to say'),
                    email=row['email'],
                    dept=row['dept'],
                    student_phone=row['student_phone'],
                    parent_phone=row['parent_phone'],
                    address=row['address'],
                    password=hashed_password,
                    photo=photo_db_path,
                    category=row['category']
                )
                db.session.add(new_user)
            db.session.commit()
        
        flash('Students and photos processed successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error processing ZIP: {str(e)}', 'error')
    finally:
        if os.path.exists(zip_filepath):
            os.remove(zip_filepath)
        if os.path.exists(temp_extract_dir):
            shutil.rmtree(temp_extract_dir)
    
    return redirect(url_for('addStudent'))


@app.route('/add_single_student', methods=['POST'])
def add_single_student():
    try:
        # Extract form data
        regd = request.form['regd']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        gender = request.form.get('gender', 'not prefer to say')
        email = request.form['email']
        dept = request.form['dept']
        student_phone = request.form['student_phone']
        parent_phone = request.form['parent_phone']
        address = request.form['address']
        password = request.form['password']
        category = request.form['category']

        # Check for existing registration number
        existing_user = User.query.filter_by(regd=regd).first()
        if existing_user:
            flash('Error: Registration number already exists', 'error')
            return redirect(url_for('addStudent'))

        # Process file upload
        if 'photo' not in request.files:
            flash('No file uploaded', 'error')
            return redirect(url_for('addStudent'))
        
        file = request.files['photo']
        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(url_for('addStudent'))
            
        if file and allowed_file(file.filename, IMAGE_EXTENSIONS):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            photo_path = filename
        else:
            flash('Invalid file type', 'error')
            return redirect(url_for('addStudent'))

       
        new_user = User(
            regd=regd,
            first_name=first_name,
            last_name=last_name,
            email=email,
            dept=dept,
            student_phone=student_phone,
            parent_phone=parent_phone,
            address=address,
            password=generate_password_hash(password),
            photo=photo_path,
            category=category
        )

        db.session.add(new_user)
        db.session.commit()

        flash('Student added successfully!', 'success')
        return redirect(url_for('addStudent'))

    except Exception as e:
        db.session.rollback()
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('addStudent'))
    
@app.route('/delete_student', methods=['POST'])
def delete_student():
    if 'username' not in session or session.get('category') != 'admin':
        flash('Unauthorized access', 'error')
        return redirect(url_for('home'))

    regd = request.form.get('regd')
    if not regd:
        flash('Please enter a registration number', 'error')
        return redirect(url_for('removeStudent'))

    student = User.query.filter_by(regd=regd).first()
    if student:
        try:
            # Delete associated permissions
            PermissionRequest.query.filter_by(student_regd=regd).delete()
            db.session.delete(student)
            db.session.commit()
            flash(f'Success! Student {regd} deleted permanently', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error deleting student: {str(e)}', 'error')
    else:
        flash(f'Student {regd} not found in database', 'error')
    
    return redirect(url_for('removeStudent'))


# CSV deletion route
@app.route('/delete_csv', methods=['POST'])
def delete_csv():
    if 'username' not in session or session.get('category') != 'admin':
        flash('Unauthorized access', 'error')
        return redirect(url_for('home'))

    if 'file' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('removeStudent'))

    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(url_for('removeStudent'))

    if file and file.filename.endswith('.csv'):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        try:
            deleted_count = 0
            with open(filepath, 'r') as csvfile:
                reader = csv.reader(csvfile)
                header = next(reader, None)
                
                if not header or 'regd' not in header:
                    flash('Invalid CSV format: Missing regd column header', 'error')
                    return redirect(url_for('removeStudent'))
                
                regd_index = header.index('regd')
                
                for row in reader:
                    if len(row) <= regd_index:
                        continue
                    regd = row[regd_index].strip()
                    if regd:
                        student = User.query.filter_by(regd=regd).first()
                        if student:
                            PermissionRequest.query.filter_by(student_regd=regd).delete()
                            db.session.delete(student)
                            deleted_count += 1
                            
                db.session.commit()
                
                if deleted_count > 0:
                    flash(f'Success! Deleted {deleted_count} students from CSV', 'success')
                else:
                    flash('No valid students found in CSV file', 'warning')
                    
            os.remove(filepath)
            
        except Exception as e:
            db.session.rollback()
            flash(f'CSV processing failed: {str(e)}', 'error')
            if os.path.exists(filepath):
                os.remove(filepath)
                
    else:
        flash('Only CSV files allowed', 'error')
    
    return redirect(url_for('removeStudent'))

@app.route('/get_student')
def get_student():
    if 'username' not in session or session.get('category') != 'admin':
        return jsonify({"error": "Unauthorized"}), 403

    regd = request.args.get('regd')
    if not regd:
        return jsonify({"error": "Registration number required"}), 400

    student = User.query.filter_by(regd=regd).first()
    if not student:
        return jsonify({"error": "Student not found"}), 404

    return jsonify({
        "regd": student.regd,
        "first_name": student.first_name,
        "last_name": student.last_name,
        "email": student.email,
        "dept": student.dept,
        "student_phone": student.student_phone,
        "parent_phone": student.parent_phone,
        "address": student.address
    })

@app.route('/modify_student', methods=['POST'])
def modify_student():
    if 'username' not in session or session.get('category') != 'admin':
        flash('Unauthorized access', 'error')
        return redirect(url_for('home'))

    original_regd = request.form.get('original_regd')
    new_regd = request.form.get('regd')
    
    try:
        student = User.query.filter_by(regd=original_regd).first()
        if not student:
            flash('Student not found', 'error')
            return redirect(url_for('modifyStudent'))

        # Check if new regd already exists
        if new_regd != original_regd and User.query.filter_by(regd=new_regd).first():
            flash('New registration number already exists', 'error')
            return redirect(url_for('modifyStudent'))

        # Update fields - Call capitalize() instead of assigning the method
        student.regd = new_regd
        student.first_name = request.form.get('first_name')
        student.last_name = request.form.get('last_name')
        student.email = request.form.get('email')
        student.dept = request.form.get('dept').capitalize()  # Fixed: Added ()
        student.student_phone = request.form.get('student_phone')
        student.parent_phone = request.form.get('parent_phone')
        student.address = request.form.get('address')

        db.session.commit()
        flash('Student details updated successfully', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating student: {str(e)}', 'error')

    return redirect(url_for('modifyStudent'))


@app.route('/get_students_by_dept')
def get_students_by_dept():
    if 'username' not in session or session.get('category') != 'admin':
        return jsonify({"error": "Unauthorized"}), 403

    dept = request.args.get('dept', '')
    
    query = User.query
    if dept:
        query = query.filter_by(dept=dept)
    
    students = query.all()
    
    student_list = [{
        "regd": s.regd,
        "first_name": s.first_name,
        "last_name": s.last_name,
        "email": s.email,
        "student_phone": s.student_phone,
        "parent_phone":s.parent_phone,
        "dept": s.dept
    } for s in students]

    return jsonify({"students": student_list})

@app.route('/add_faculty', methods=['POST'])
def add_faculty():
    try:
        # Get form data
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        dept = request.form.get('dept')
        faculty_phone = request.form.get('faculty_phone')
        room_no = request.form.get('room_no')
        category = request.form.get('category').upper()
        password = request.form.get('password')
        photo = request.files.get('photo')

        # Hash the password
        hashed_password = generate_password_hash(password)

        # Save the photo (if provided)
        photo_path = None
        if photo:
            photo_filename = secure_filename(photo.filename)
            photo_path = os.path.join(app.config['UPLOAD_FOLDER'], photo_filename)
            photo.save(photo_path)
            photo_path = f"static/uploads/{photo_filename}"

        # Create a new Faculty object
        new_faculty = Faculty(
            first_name=first_name,
            last_name=last_name,
            email=email,
            dept=dept,
            faculty_phone=faculty_phone,
            room_no=room_no,
            category=category,
            password_hash=hashed_password,
            photo=photo_path
        )

        # Add to the database
        db.session.add(new_faculty)
        db.session.commit()

        return jsonify({"success": True, "message": "Faculty member added successfully!"})

    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/remove_faculty', methods=['POST'])
def remove_faculty():
    try:
        data = request.get_json()
        email = data.get('email')

        if not email:
            return jsonify({"success": False, "message": "Email is required."}), 400

        # Find the faculty member by email
        faculty = Faculty.query.filter_by(email=email).first()

        if not faculty:
            return jsonify({"success": False, "message": "Faculty member not found."}), 404

        # Delete the faculty member from the database
        db.session.delete(faculty)
        db.session.commit()

        return jsonify({"success": True, "message": "Faculty member removed successfully!"})

    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/get_faculty_by_department', methods=['GET'])
def get_faculty_by_department():
    try:
        department = request.args.get('department')

        if not department:
            return jsonify({"success": False, "message": "Department is required."}), 400

        # Find all faculty members in the department
        faculty_members = Faculty.query.filter_by(dept=department).all()

        if not faculty_members:
            return jsonify({"success": False, "message": "No faculty members found in this department."}), 404

        # Return faculty details
        faculty_data = [
            {
                "first_name": faculty.first_name,
                "last_name": faculty.last_name,
                "email": faculty.email,
                "dept": faculty.dept,
                "faculty_phone": faculty.faculty_phone,
                "room_no": faculty.room_no,
                "category": faculty.category,
                "photo": faculty.photo if faculty.photo else "No photo available.jpg"
            }
            for faculty in faculty_members
        ]

        return jsonify({"success": True, "faculty": faculty_data})

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/get_faculty', methods=['GET'])
def get_faculty():
    try:
        email = request.args.get('email')

        if not email:
            return jsonify({"success": False, "message": "Email is required."}), 400

        # Find the faculty member by email
        faculty = Faculty.query.filter_by(email=email).first()

        if not faculty:
            return jsonify({"success": False, "message": "Faculty member not found."}), 404

        # Return faculty details
        faculty_data = {
            "first_name": faculty.first_name,
            "last_name": faculty.last_name,
            "email": faculty.email,
            "dept": faculty.dept,
            "faculty_phone": faculty.faculty_phone,
            "room_no": faculty.room_no,
            "category": faculty.category,
        }

        return jsonify({"success": True, "faculty": faculty_data})

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500




@app.route('/modify_faculty', methods=['POST'])
def modify_faculty():
    try:
        # Get form data
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        new_email = request.form.get('email')  # New email from the form
        dept = request.form.get('dept')
        faculty_phone = request.form.get('faculty_phone')
        room_no = request.form.get('room_no')
        category = request.form.get('category').upper()
        photo = request.files.get('photo')
        original_email = request.form.get('original_email')  # Original email from the hidden field

        # Find the faculty member by the original email
        faculty = Faculty.query.filter_by(email=original_email).first()

        if not faculty:
            return jsonify({"success": False, "message": "Faculty member not found."}), 404

        # Check if the new email is already in use by another faculty member
        if new_email != original_email:  # Only check if the email is being changed
            existing_faculty = Faculty.query.filter_by(email=new_email).first()
            if existing_faculty:
                return jsonify({"success": False, "message": "Email is already in use by another faculty member."}), 400

        # Update faculty details (including email)
        faculty.first_name = first_name
        faculty.last_name = last_name
        faculty.email = new_email  # Update email
        faculty.dept = dept
        faculty.faculty_phone = faculty_phone
        faculty.room_no = room_no
        faculty.category = category

        # Update photo (if provided)
        if photo:
            photo_filename = secure_filename(photo.filename)
            photo_path = os.path.join(app.config['UPLOAD_FOLDER'], photo_filename)
            photo.save(photo_path)
            faculty.photo = f"static/uploads/{photo_filename}"

        # Commit changes to the database
        db.session.commit()

        return jsonify({"success": True, "message": "Faculty details updated successfully!"})

    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/get_all_faculty', methods=['GET'])
def get_all_faculty():
    try:
        # Fetch all faculty members from the database
        faculty_members = Faculty.query.all()

        if not faculty_members:
            return jsonify({"success": False, "message": "No faculty members found."}), 404

        # Return faculty details
        faculty_data = [
            {
                "first_name": faculty.first_name,
                "last_name": faculty.last_name,
                "email": faculty.email,
                "dept": faculty.dept,
                "faculty_phone": faculty.faculty_phone,
                "room_no": faculty.room_no,
                "category": faculty.category,
                "photo": faculty.photo or "static/uploads/default.jpg",  # Default photo if none is provided
            }
            for faculty in faculty_members
        ]

        return jsonify({"success": True, "faculty": faculty_data})

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

if __name__ == '__main__':
    with app.app_context():
        try:
            db.create_all()
            print("Database connection successful!")
        except Exception as e:
            print(f"Database connection failed: {e}")
        
    scheduler = BackgroundScheduler()
    scheduler.add_job(func=check_expired_permissions_and_notify, trigger="interval", minutes=2)
    scheduler.add_job(func=delete_expired_qr_codes, trigger="interval", minutes=30)
    scheduler.start()
    atexit.register(lambda: scheduler.shutdown())  
    app.run(port=5002,debug=True)   
