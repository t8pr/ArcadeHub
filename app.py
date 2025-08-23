from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import supabase
from flask_mail import Mail, Message
from supabase import create_client, Client
import os
import re
from dotenv import load_dotenv
from Games import GAMES 
from werkzeug.security import generate_password_hash, check_password_hash
import uuid  # ← ADD THIS LINE
from urllib.parse import urlparse, urljoin
import random
import datetime
from datetime import datetime, timezone, timedelta
# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'fallback-secret-key')

# Initialize Supabase
supabase_url = os.getenv('SUPABASE_URL')
supabase_key = os.getenv('SUPABASE_KEY')
supabase_client: Client = create_client(supabase_url, supabase_key)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# After app initialization
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

mail = Mail(app)
# After app initialization
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

mail = Mail(app)
# After supabase_client initialization, add:
try:
    supabase_url = os.getenv('SUPABASE_URL')
    supabase_key = os.getenv('SUPABASE_KEY')  # Should be service_role key
    
    if not supabase_url or not supabase_key:
        raise ValueError("Supabase URL or key missing from .env file")
    
    supabase_client: Client = create_client(supabase_url, supabase_key)
    print("✅ Supabase client initialized successfully")
    
except Exception as e:
    print(f"❌ Failed to initialize Supabase: {e}")
    supabase_client = None

class User(UserMixin):
    def __init__(self, id, email, username, account_type, created_at=None):
        self.id = id
        self.email = email
        self.username = username
        self.account_type = account_type
        self.created_at = created_at

    def is_developer(self):
        return self.account_type == 'developer'

@login_manager.user_loader
def load_user(user_id):
    if not supabase_client:
        return None
        
    try:
        response = supabase_client.table('users').select('id, email, username, account_type, created_at').eq('id', user_id).execute()        
        if response.data:
            user_data = response.data[0]
            return User(
                id=user_data['id'],
                email=user_data['email'],
                username=user_data['username'],
                account_type=user_data['account_type'],
                created_at=user_data.get('created_at')  # Add this line
            )
    except Exception as e:
        print(f"Error loading user: {e}")
    return None


# ===== ROUTES =====

@app.template_filter('format_date')
def format_date_filter(value):
    if isinstance(value, str):
        try:
            # Parse ISO format string
            dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
            return dt.strftime('%Y-%m-%d %H:%M')
        except:
            return value
    elif hasattr(value, 'strftime'):
        # It's already a datetime object
        return value.strftime('%Y-%m-%d %H:%M')
    return value

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if not supabase_client:
        flash('❌ نظام التسجيل غير متاح حالياً', 'error')
        return render_template('register.html')
    
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        username = request.form['username'].strip()
        password = request.form['password']
        account_type = request.form.get('account_type', 'user')
        
        # Validation
        errors = []
        
        # Email validation
        if not email or '@' not in email or '.' not in email:
            errors.append('صيغة البريد الإلكتروني غير صحيحة')
        
        # Username validation
        if not username or len(username) < 3:
            errors.append('اسم المستخدم يجب أن يكون 3 أحرف على الأقل')
        elif len(username) > 20:
            errors.append('اسم المستخدم يجب أن لا يتجاوز 20 حرف')
        elif not username.isalnum():
            errors.append('اسم المستخدم يجب أن يحتوي على أحرف وأرقام فقط')
        
        # Password validation
        if len(password) < 8:
            errors.append('كلمة المرور يجب أن تكون 8 أحرف على الأقل')
        elif not any(char.isdigit() for char in password):
            errors.append('كلمة المرور يجب أن تحتوي على رقم واحد على الأقل')
        elif not any(char.isupper() for char in password):
            errors.append('كلمة المرور يجب أن تحتوي على حرف كبير واحد على الأقل')
        
        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('register.html')
        
        try:
            # Check if email already exists
            email_check = supabase_client.table('users').select('email').eq('email', email).execute()
            if email_check.data:
                flash('البريد الإلكتروني مسجل مسبقاً', 'error')
                return render_template('register.html')
            
            # Check if username already exists
            username_check = supabase_client.table('users').select('username').eq('username', username).execute()
            if username_check.data:
                flash('اسم المستخدم مسجل مسبقاً', 'error')
                return render_template('register.html')
            
            # Create user
            hashed_password = generate_password_hash(password)
            new_user = {
                'email': email,
                'username': username,
                'password': hashed_password,
                'account_type': account_type
            }
            
            response = supabase_client.table('users').insert(new_user).execute()
            
            if response.data:
                user_data = response.data[0]
                user = User(
                    id=user_data['id'],
                    email=user_data['email'],
                    username=user_data['username'],
                    account_type=user_data['account_type']
                )
                login_user(user)
                flash(f'تم إنشاء الحساب بنجاح! مرحباً {username}', 'success')
                
                # Redirect based on account type
                if account_type == 'developer':
                    flash('يمكنك الآن رفع الألعاب الخاصة بك', 'info')
                    return redirect(url_for('upload'))
                else:
                    flash('يمكنك الآن استكشاف وتحميل الألعاب', 'info')
                    return redirect(url_for('games'))
            else:
                flash('فشل في إنشاء الحساب', 'error')
                
        except Exception as e:
            flash('حدث خطأ في إنشاء الحساب', 'error')
            print(f"Registration error: {e}")
            
    return render_template('register.html')

@app.route('/api/check-email/<email>')
def check_email(email):
    try:
        response = supabase_client.table('users').select('email').eq('email', email).execute()
        return {'available': len(response.data) == 0}
    except:
        return {'available': False}

@app.route('/api/check-username/<username>')
def check_username(username):
    try:
        response = supabase_client.table('users').select('username').eq('username', username).execute()
        return {'available': len(response.data) == 0}
    except:
        return {'available': False}

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

@login_manager.unauthorized_handler
def unauthorized():
    flash('يجب تسجيل الدخول للوصول إلى هذه الصفحة', 'error')
    return redirect(url_for('login', next=request.endpoint))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('account'))
    
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        try:
            # Get user from Supabase
            response = supabase_client.table('users').select('*').eq('email', email).execute()
            
            if response.data:
                user_data = response.data[0]
                
                # Check password
                if check_password_hash(user_data['password'], password):
                    user = User(
                        id=user_data['id'],
                        email=user_data['email'],
                        username=user_data['username'],
                        account_type=user_data['account_type']
                    )
                    login_user(user)
                    flash('تم تسجيل الدخول بنجاح!', 'success')
                    
                    # Redirect to intended page or account
                    next_page = request.args.get('next')
                    return redirect(next_page or url_for('account'))
                else:
                    flash('كلمة المرور غير صحيحة', 'error')
            else:
                flash('البريد الإلكتروني غير مسجل', 'error')
                
        except Exception as e:
            flash('حدث خطأ أثناء تسجيل الدخول', 'error')
            print(f"Login error: {e}")
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('تم تسجيل الخروج بنجاح', 'success')
    return redirect(url_for('home'))

@app.route('/account')
@login_required
def account():
    return render_template('account.html', user=current_user)

@app.route('/update-username', methods=['POST'])
@login_required
def update_username():
    try:
        # Get the username from form data
        new_username = request.form.get('new_username', '').strip()
        
        if not new_username:
            flash('لم يتم تقديم اسم مستخدم', 'error')
            return redirect(url_for('account') + '#profile')
        
        # Validation
        if len(new_username) < 3:
            flash('اسم المستخدم يجب أن يكون 3 أحرف على الأقل', 'error')
            return redirect(url_for('account') + '#profile')
        
        if len(new_username) > 20:
            flash('اسم المستخدم يجب أن لا يتجاوز 20 حرف', 'error')
            return redirect(url_for('account') + '#profile')
        
        if not re.match(r'^[a-zA-Z0-9\u0600-\u06FF]+$', new_username):
            flash('اسم المستخدم يجب أن يحتوي على أحرف وأرقام فقط', 'error')
            return redirect(url_for('account') + '#profile')
        
        # Check if username already exists (excluding current user)
        existing_user = supabase_client.table('users').select('username').eq('username', new_username).neq('id', current_user.id).execute()
        
        if existing_user.data:
            flash('اسم المستخدم مسجل مسبقاً', 'error')
            return redirect(url_for('account') + '#profile')
        
        # Update username in database
        update_response = supabase_client.table('users').update({
            'username': new_username,
            'updated_at': datetime.now(timezone.utc).isoformat()
        }).eq('id', current_user.id).execute()
        
        if update_response.data:
            # Update the current user object
            current_user.username = new_username
            flash('تم تحديث اسم المستخدم بنجاح', 'success')
        else:
            flash('فشل في تحديث اسم المستخدم', 'error')
            
    except Exception as e:
        flash('حدث خطأ في تحديث اسم المستخدم', 'error')
        print(f"Username update error: {e}")
    
    return redirect(url_for('account') + '#profile')

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    # Check if we have user data in session
    if 'reset_user_id' not in session or 'reset_email' not in session:
        flash('يرجى طلب إعادة تعيين كلمة المرور أولاً', 'error')
        return redirect(url_for('forgot_password'))
    
    # Get the actual user data from session
    user_id = session['reset_user_id']
    user_email = session['reset_email']  # The actual account email
    
    if request.method == 'POST':
        otp_code = request.form['otp_code'].strip()
        
        # Basic OTP validation
        if not otp_code or len(otp_code) != 6 or not otp_code.isdigit():
            flash('رمز التحقق يجب أن يكون 6 أرقام', 'error')
            return render_template('verify_otp.html')
        
        try:
            # Check OTP attempts
            if session.get('otp_attempts', 0) >= 3:
                flash('لقد تجاوزت عدد المحاولات المسموح بها', 'error')
                session.clear()
                return redirect(url_for('forgot_password'))
            
            # ✅ CRITICAL: Verify OTP for this specific user ID and email
            response = supabase_client.table('password_resets').select('*').eq('user_id', user_id).eq('email', user_email).eq('otp_code', otp_code).eq('used', False).execute()
            
            if response.data:
                otp_data = response.data[0]
                
                # Check if OTP is expired
                expires_at = datetime.fromisoformat(otp_data['expires_at'].replace('Z', '+00:00')).replace(tzinfo=timezone.utc)
                current_time = datetime.now(timezone.utc)
                
                if current_time > expires_at:
                    flash('انتهت صلاحية رمز التحقق', 'error')
                    session['otp_attempts'] = session.get('otp_attempts', 0) + 1
                    return render_template('verify_otp.html')
                
                # Mark OTP as used
                supabase_client.table('password_resets').update({'used': True}).eq('id', otp_data['id']).execute()
                
                # Store verification status in session
                session['verified_for_reset'] = True
                session.pop('otp_attempts', None)
                
                flash('تم التحقق بنجاح، يمكنك الآن تعيين كلمة مرور جديدة', 'success')
                return redirect(url_for('set_new_password'))
            else:
                session['otp_attempts'] = session.get('otp_attempts', 0) + 1
                remaining_attempts = 3 - session['otp_attempts']
                if remaining_attempts > 0:
                    flash(f'رمز التحقق غير صحيح. لديك {remaining_attempts} محاولات متبقية', 'error')
                else:
                    flash('لقد استنفذت جميع محاولات التحقق', 'error')
                    session.clear()
                    return redirect(url_for('forgot_password'))
                
        except Exception as e:
            flash('حدث خطأ في التحقق', 'error')
            print(f"OTP verification error: {e}")
    
    # Show which email the OTP was sent to
    return render_template('verify_otp.html', user_email=user_email)

@app.route('/cleanup-expired-otps')
def cleanup_expired_otps():
    """Clean up expired OTPs (can be called periodically)"""
    try:
        current_time = datetime.now(timezone.utc).isoformat()
        result = supabase_client.table('password_resets').delete().lt('expires_at', current_time).execute()
        print(f"✅ Cleaned up {len(result.data)} expired OTPs")
        return f"Cleaned up {len(result.data)} expired OTPs"
    except Exception as e:
        print(f"❌ Cleanup error: {e}")
        return f"Cleanup error: {e}"

def send_otp_email(email, otp_code, username):
    """
    Send OTP email with proper Unicode encoding for Arabic
    """
    email_user = os.getenv('MAIL_USERNAME')
    email_password = os.getenv('MAIL_PASSWORD')
    
    # If no email credentials are set, use fallback
    if not email_user or not email_password:
        flash(f'في وضع التطوير', 'info')
        return True
    
    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        from email.header import Header
        
        # Create message with proper encoding
        msg = MIMEMultipart()
        
        # Set subject with proper encoding for Arabic
        subject = "رمز التحقق - SaudiArcade"
        msg['Subject'] = Header(subject, 'utf-8')
        
        # Set from and to with proper encoding
        msg['From'] = Header("SaudiArcade", 'utf-8')
        msg['To'] = Header(email, 'utf-8')
        
        # Create email body with Arabic text
        arabic_body = f"""
        مرحباً {username},
        
        رمز التحقق الخاص بك هو: {otp_code}
        
        ⏰ هذا الرمز صالح لمدة 15 دقيقة فقط
        
        إذا لم تطلب إعادة تعيين كلمة المرور، يرجى تجاهل هذا البريد.
        
        شكراً لك،
        فريق منصة سعودي أركيد
        """
        
        # Create both plain text and HTML versions
        plain_text = MIMEText(arabic_body, 'plain', 'utf-8')
        msg.attach(plain_text)
        
        # Connect and send with proper encoding
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()  # Important for UTF-8 support
            server.login(email_user, email_password)
            
            # Send with explicit UTF-8 encoding
            server.sendmail(
                email_user, 
                [email], 
                msg.as_string().encode('utf-8')
            )
        
        print(f"✅ Email sent successfully to {email}")
        flash('تم إرسال رمز التحقق إلى بريدك الإلكتروني', 'success')
        return True
        
    except Exception as e:
        print(f"❌ Email failed: {e}")
        # Fallback to showing OTP on screen
        flash(f'لم نتمكن من إرسال البريد. رمز التحقق هو: {otp_code}', 'warning')
        return True
    
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        
        # Basic email validation
        if not email or '@' not in email:
            flash('صيغة البريد الإلكتروني غير صحيحة', 'error')
            return render_template('forgot_password.html')
        
        try:
            # Check if email exists in database and get user data
            response = supabase_client.table('users').select('id, email, username').eq('email', email).execute()
            
            if response.data:
                user_data = response.data[0]
                user_id = user_data['id']
                username = user_data['username']
                user_email = user_data['email']  # The actual email from database
                
                # ✅ CRITICAL: Verify the entered email matches the account email
                if email != user_email:
                    flash('البريد الإلكتروني لا يتطابق مع حساب المستخدم', 'error')
                    return render_template('forgot_password.html')
                
                # Generate OTP (6-digit code)
                otp_code = str(random.randint(100000, 999999))
                
                # Use timezone-aware datetime
                otp_expires = datetime.now(timezone.utc) + timedelta(minutes=15)
                
                # Store OTP in database for this specific user
                reset_data = {
                    'user_id': user_id,  # Store user ID for extra verification
                    'email': user_email,  # Use the email from database, not form
                    'otp_code': otp_code,
                    'expires_at': otp_expires.isoformat(),
                    'used': False
                }
                
                # Insert into password_resets table
                reset_response = supabase_client.table('password_resets').insert(reset_data).execute()
                
                if reset_response.data:
                    # 🔥 SEND OTP TO THE USER'S REGISTERED EMAIL
                    email_sent = send_otp_email(user_email, otp_code, username)
                    
                    if email_sent:
                        flash(f'تم إرسال رمز التحقق إلى بريدك المسجل: {user_email}', 'success')
                    else:
                        flash(f'تم إنشاء رمز التحقق ولكن حدث خطأ في الإرسال إلى {user_email}', 'warning')
                    
                    # Store both user ID and email for verification
                    session['reset_user_id'] = user_id
                    session['reset_email'] = user_email  # The actual account email
                    session['otp_attempts'] = 0
                    session['otp_created_at'] = datetime.now(timezone.utc).isoformat()
                    
                    return redirect(url_for('verify_otp'))
                else:
                    flash('فشل في إنشاء رمز التحقق', 'error')
            else:
                flash('البريد الإلكتروني غير مسجل في النظام', 'error')
                
        except Exception as e:
            flash('حدث خطأ في إرسال رمز التحقق', 'error')
            print(f"Forgot password error: {e}")
    
    return render_template('forgot_password.html')

@app.route('/debug-email')
def debug_email():
    """Debug email configuration"""
    email_user = os.getenv('MAIL_USERNAME')
    email_password = os.getenv('MAIL_PASSWORD')
    
    return f"""
    Email User: {email_user}<br>
    Email Password: {email_password}<br>
    Server: {os.getenv('MAIL_SERVER')}<br>
    Port: {os.getenv('MAIL_PORT')}
    """

@app.route('/test-email')
def test_email():
    try:
        # Test email configuration
        msg = Message(
            subject='Test Email from SaudiArcade',
            recipients=['test@example.com'],
            body='This is a test email from your Flask application.'
        )
        mail.send(msg)
        return '✅ Email sent successfully!'
    except Exception as e:
        return f'❌ Email failed: {str(e)}'

@app.route('/set-new-password', methods=['GET', 'POST'])
def set_new_password():
    # Check if we have the user data and it's verified
    if 'reset_user_id' not in session or 'reset_email' not in session or not session.get('verified_for_reset'):
        flash('يرجى التحقق أولاً', 'error')
        return redirect(url_for('forgot_password'))
    
    # Get the actual user data from session
    user_id = session['reset_user_id']
    user_email = session['reset_email']  # The actual account email
    
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if new_password != confirm_password:
            flash('كلمات المرور غير متطابقة', 'error')
            return render_template('set_new_password.html')
        
        if len(new_password) < 8:
            flash('كلمة المرور يجب أن تكون 8 أحرف على الأقل', 'error')
            return render_template('set_new_password.html')
        
        try:
            # ✅ CRITICAL: Update password for this specific user ID
            hashed_password = generate_password_hash(new_password)
            update_response = supabase_client.table('users').update({
                'password': hashed_password,
                'updated_at': datetime.now(timezone.utc).isoformat()
            }).eq('id', user_id).execute()  # Use user ID for security
            
            if update_response.data:
                # Clean up session and OTP records for this user
                session.clear()
                
                # Delete all OTPs for this user
                supabase_client.table('password_resets').delete().eq('user_id', user_id).execute()
                
                flash('تم إعادة تعيين كلمة المرور بنجاح', 'success')
                return redirect(url_for('login'))
            else:
                flash('فشل في إعادة تعيين كلمة المرور', 'error')
                
        except Exception as e:
            flash('حدث خطأ في إعادة تعيين كلمة المرور', 'error')
            print(f"Password reset error: {e}")
    
    return render_template('set_new_password.html')
    
@app.route('/change-password', methods=['POST'])
@login_required
def change_password():  # ← This name must match url_for('change_password')
    current_password = request.form['current_password']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']
    
    # Validation
    if new_password != confirm_password:
        flash('كلمات المرور غير متطابقة', 'error')
        return redirect(url_for('account') + '#security')
    
    if len(new_password) < 8:
        flash('كلمة المرور يجب أن تكون 8 أحرف على الأقل', 'error')
        return redirect(url_for('account') + '#security')
    
    try:
        # Get current user's password from database
        response = supabase_client.table('users').select('password').eq('id', current_user.id).execute()
        
        if not response.data:
            flash('المستخدم غير موجود', 'error')
            return redirect(url_for('account') + '#security')
        
        current_hashed_password = response.data[0]['password']
        
        # Verify current password
        if not check_password_hash(current_hashed_password, current_password):
            flash('كلمة المرور الحالية غير صحيحة', 'error')
            return redirect(url_for('account') + '#security')
        
        # Update password in database
        new_hashed_password = generate_password_hash(new_password)
        update_response = supabase_client.table('users').update({
            'password': new_hashed_password,
            'updated_at': datetime.datetime.now().isoformat()
        }).eq('id', current_user.id).execute()
        
        if update_response.data:
            flash('تم تغيير كلمة المرور بنجاح', 'success')
            # Log the user out for security
            logout_user()
            flash('يرجى تسجيل الدخول مرة أخرى بكلمة المرور الجديدة', 'info')
            return redirect(url_for('login'))
        else:
            flash('فشل في تغيير كلمة المرور', 'error')
            
    except Exception as e:
        flash('حدث خطأ في تغيير كلمة المرور', 'error')
        print(f"Password change error: {e}")
    
    return redirect(url_for('account') + '#security')

@app.route('/upload')
@login_required
def upload():
    if not current_user.is_developer():
        flash('يجب أن تكون مطوراً لرفع الألعاب', 'error')
        return redirect(url_for('account'))
    return render_template('upload.html')

@app.route('/games')
def games():
    return render_template('games.html', games=GAMES)

@app.route('/games/<game_slug>')
def game_details(game_slug):
    game = next((g for g in GAMES if g['slug'] == game_slug), None)
    if not game:
        return "Game not found", 404
    
    if 'youtube.com' in game['video_url']:
        game['safe_video_url'] = game['video_url'].replace('watch?v=', 'embed/')
    else:
        game['safe_video_url'] = game['video_url']
    
    return render_template('game_details.html', game=game)

if __name__ == '__main__':
    app.run(debug=True)