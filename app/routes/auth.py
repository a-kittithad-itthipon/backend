import random
from flask import Blueprint, request, current_app
from flask_jwt_extended import create_access_token, jwt_required, get_jwt, get_jwt_identity
from flask_mail import Mail, Message
from datetime import timedelta, datetime

from app import bcrypt, mail, jwt
from app.services.db import get_db_connection
from app.utils.responses import success, error
from app.utils.validators import require_json_fields


auth_bp = Blueprint("auth", __name__)


# --- LOGIN ROUTE ---
@auth_bp.route('/api/auth/login', methods=['POST'])
@require_json_fields(["username", "password"])
def login():
    conn = None
    try:
        body = request.json
        username = body.get('username')
        password = body.get('password')

        conn = get_db_connection()
        cursor = conn.cursor()

        # Fetch user details
        cursor.execute(
            'SELECT id, username, password, role FROM users WHERE username=%s', (username,))
        data = cursor.fetchone()

        if not data or not bcrypt.check_password_hash(data['password'], password):
            return error(message='Invalid username or password', error_code='INVALID_CREDENTIALS', status=401)

        # Create JWT Token
        token = create_access_token(
            identity=str(data['id']),
            additional_claims={'role': data['role']},
            expires_delta=timedelta(minutes=10)
        )

        return success(
            message='Login successful',
            data={
                'role': data['role'],
                'access_token': token
            },
            status=200
        )

    except Exception as err:
        # This will show the exact error in your terminal
        print(f"Debug Error: {err}")
        if conn:
            conn.rollback()
        return error(message='Internal server error', error_code='INTERNAL_SERVER_ERROR', status=500)
    finally:
        if conn:
            conn.close()


# --- REGISTER ROUTE ---
@auth_bp.route('/api/auth/register', methods=['POST'])
@require_json_fields(["username", "email", "password"])
def register():
    conn = None
    try:
        body = request.json
        username, email, password = body.get(
            'username'), body.get('email'), body.get('password')
        create_db = body.get('create_db', False)

        pw_hash = bcrypt.generate_password_hash(password).decode()

        conn = get_db_connection()
        cursor = conn.cursor()

        # Check for duplicate user/email
        cursor.execute(
            "SELECT id FROM users WHERE username = %s OR email = %s", (username, email))
        if cursor.fetchone():
            return error(message='Username or email already exists', error_code='ALREADY_EXISTS', status=409)

        if create_db:
            db_name = f"db_{username}"
            # Manage Database and User Permissions
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {db_name}")
            cursor.execute(
                f"CREATE USER IF NOT EXISTS %s@'%%' IDENTIFIED BY %s", (username, password))
            cursor.execute(
                f"GRANT ALL PRIVILEGES ON {db_name}.* TO %s@'%%'", (username,))
            cursor.execute("FLUSH PRIVILEGES")

        # Save user record
        cursor.execute(
            "INSERT INTO users (username, email, password, db) VALUES (%s, %s, %s, %s)",
            (username, email, pw_hash, create_db)
        )

        conn.commit()
        return success(message='Account created successfully', data={'user': {'username': username}}, status=200)

    except Exception as err:
        # This will show the exact error in your terminal
        print(f"Debug Error: {err}")
        if conn:
            conn.rollback()
        return error(message='Internal server error', error_code='INTERNAL_SERVER_ERROR', status=500)
    finally:
        if conn:
            conn.close()


# --- REQUEST OTP ROUTE ---
@auth_bp.route('/api/auth/reset-password/request', methods=['POST'])
@require_json_fields(['username'])
def otp_request():
    conn = None
    try:
        username = request.json.get('username')
        conn = get_db_connection()
        cursor = conn.cursor()

        # 1. Verify user existence
        cursor.execute(
            'SELECT id, email FROM users WHERE username = %s', (username,))
        data = cursor.fetchone()

        # Security: Return fake success for non-existent users to prevent account enumeration
        if not data:
            return success(message="If this user exists, an OTP has been sent.", data={}, status=200)

        user_id = data['id']

        # 2. Enforce Rate Limiting (1-minute cooldown)
        one_minute_ago = datetime.now() - timedelta(minutes=1)
        cursor.execute('''
            SELECT id FROM otp_requests
            WHERE user_id = %s AND created_at > %s
        ''', (user_id, one_minute_ago))

        if cursor.fetchone():
            return error(message='Please wait 1 minute before requesting a new OTP', error_code='RATE_LIMIT', status=429)

        # 3. Generate and Securely Hash OTP
        otp_plain = f"{random.randint(100000, 999999)}"
        otp_hash = bcrypt.generate_password_hash(otp_plain).decode()
        expired_at = datetime.now() + timedelta(minutes=5)

        # 4. Database Operations: Invalidate old OTPs and store the new one
        cursor.execute(
            'UPDATE otp_requests SET is_used = 1 WHERE user_id = %s AND is_used = 0', (user_id,))
        cursor.execute(
            'INSERT INTO otp_requests (user_id, otp_code, expired_at) VALUES (%s, %s, %s)',
            (user_id, otp_hash, expired_at)
        )

        # Commit changes to database
        conn.commit()

        # 5. Generate Temporary JWT (request_token)
        # We include 'username' and 'purpose' for the verification step
        token = create_access_token(
            identity=str(user_id),
            additional_claims={
                'purpose': 'request_reset_password',
            },
            expires_delta=timedelta(minutes=5)
        )

        # 6. Prepare Email Notification
        mail_otp = Message(
            subject='Your Reset Password OTP',
            recipients=[data['email']],
            body=f"Your OTP is: {otp_plain}. It will expire in 5 minutes."
        )

        # 7. Send Email (Handling potential SMTP failures)
        try:
            mail.send(mail_otp)
        except Exception as e:
            # Log the error but consider if you want to tell the user the email failed
            print(f"Mail sending failed: {e}")

        return success(message='OTP sent successfully', data={'request_token': token}, status=200)

    except Exception as err:
        # Log unexpected errors for debugging
        print(f"Debug Error: {err}")
        if conn:
            conn.rollback()
        return error(message='Internal server error', error_code='INTERNAL_SERVER_ERROR', status=500)
    finally:
        # Ensure database connection is always closed
        if conn:
            conn.close()


# --- RESEND OTP ROUTE ---
@auth_bp.route('/api/auth/reset-password/resend-otp', methods=['POST'])
# --- VERIFY OTP ROUTE ---
@auth_bp.route('/api/auth/reset-password/verify-otp', methods=['POST'])
@require_json_fields(["otp_code"])
@jwt_required()
def verify_otp():
    conn = None

    try:
        body = request.json
        otp_input = body.get('otp_code')

        # Extract data from the JWT
        user_id = get_jwt_identity()
        claims = get_jwt()

        # Security: Ensure this token was issued specifically for password reset request
        if claims.get('purpose') != 'request_reset_password':
            return error(message='Invalid token purpose', error_code='UNAUTHORIZED', status=401)

        conn = get_db_connection()
        cursor = conn.cursor()

        # Fetch the latest active OTP for this user
        # Note: No JOIN with users table needed since user_id is already verified via JWT
        cursor.execute('''
                SELECT id, user_id, otp_code, expired_at, attempts
                FROM otp_requests
                WHERE user_id = %s AND is_used = 0
                ORDER BY id DESC LIMIT 1
        ''', (user_id,))
        data = cursor.fetchone()

        # 1. Check if an active OTP request exists
        if not data:
            return error(message='No active OTP found', error_code='NOT_FOUND', status=404)

        # 2. Check if the OTP has expired
        if datetime.now() > data['expired_at']:
            return error(message="OTP has expired", error_code='OTP_EXPIRED', status=400)

        # 3. Check for too many failed attempts (Brute-force protection)
        if data['attempts'] >= 3:
            cursor.execute(
                'UPDATE otp_requests SET is_used = 1 WHERE id = %s', (data['id'],))
            conn.commit()
            return error(message='Too many failed attempts.', error_code='TOO_MANY_FAILED_ATTEMPTS', status=400)

        # 4. Validate OTP using Bcrypt hash comparison
        if bcrypt.check_password_hash(data['otp_code'], otp_input):
            # Success: Mark this OTP as used
            cursor.execute(
                'UPDATE otp_requests SET is_used = 1 WHERE id = %s', (data['id'],))
            conn.commit()

            # Issue a new token with higher authority for the final password reset step
            # purpose 'otp_verified' acts as proof that the user passed the OTP stage
            token = create_access_token(
                identity=str(user_id),
                additional_claims={
                    'purpose': 'otp_verified',
                },
                expires_delta=timedelta(minutes=5)
            )

            return success(message='OTP verified successfully', data={'verify_token': token}, status=200)

        else:
            # Failure: Increment failed attempts counter
            cursor.execute(
                'UPDATE otp_requests SET attempts = attempts + 1 WHERE id = %s', (data['id'],))
            conn.commit()
            return error(message='Invalid OTP code', error_code='INVALID_OTP_CODE', status=400)

    except Exception as err:
        # Detailed error log in the terminal for the developer
        print(f"Debug Error: {err}")
        if conn:
            conn.rollback()
        return error(message='Internal server error', error_code='INTERNAL_SERVER_ERROR', status=500)
    finally:
        # Ensure database connection is closed safely
        if conn:
            conn.close()


# --- SET PASSWORD ROUTE ---
@auth_bp.route('/api/auth/reset-password/confirm', methods=['POST'])
@require_json_fields(["password"])
@jwt_required()
def confirm_password():
    conn = None

    try:
        body = request.json
        new_password = body.get('password')

        # Extract data from the JWT
        user_id = get_jwt_identity()
        claims = get_jwt()

        # Security: Ensure this token was issued specifically for set password request
        if claims.get('purpose') != 'otp_verified':
            return error(message='Invalid token purpose', error_code='UNAUTHORIZED', status=401)

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT password FROM users WHERE id = %s', (user_id,))
        result = cursor.fetchone()

        # Check if new password is same as old password
        if bcrypt.check_password_hash(result['password'], new_password):
            return error(
                message='You have already used this password. Please choose a new one.',
                error_code='PASSWORD_HAS_BEEN_USED',
                status=409
            )

        # Otherwise → hash & save new password
        new_hash = bcrypt.generate_password_hash(new_password)

        # Update new password
        cursor.execute("UPDATE users SET password = %s WHERE id = %s",
                       (new_hash, user_id))
        conn.commit()

        return success(message='Update password successfully', data={}, status=200)

    except Exception as err:
        # Detailed error log in the terminal for the developer
        print(f"Debug Error: {err}")
        if conn:
            conn.rollback()
        return error(message='Internal server error', error_code='INTERNAL_SERVER_ERROR', status=500)
    finally:
        # Ensure database connection is closed safely
        if conn:
            conn.close()
