from flask import Flask, jsonify, request
import pymysql
import random
from dotenv import load_dotenv
from flask_mail import Mail, Message
import os
from flask_bcrypt import Bcrypt
from datetime import timedelta
from flask_jwt_extended import get_jwt
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity,
)
from werkzeug.utils import secure_filename
import zipfile
import shutil
import yaml

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
app.config["JWT_DECODE_LEEWAY"] = timedelta(minutes=5)
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=4)
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_USERNAME")

bcrypt = Bcrypt(app)
jwt = JWTManager(app)
mail = Mail(app)


def get_db_connection():
    return pymysql.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASS"),
        database=os.getenv("DB_NAME"),
        cursorclass=pymysql.cursors.DictCursor,
    )

def unzip_here(zip_path, target_dir):
    os.makedirs(target_dir, exist_ok=True)

    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(target_dir)

    while True:
        items = os.listdir(target_dir)
        if len(items) != 1:
            break

        nested = os.path.join(target_dir, items[0])
        if not os.path.isdir(nested):
            break

        for item in os.listdir(nested):
            src = os.path.join(nested, item)
            dst = os.path.join(target_dir, item)
            if os.path.exists(dst):
                if os.path.isdir(dst):
                    shutil.rmtree(dst)
                else:
                    os.remove(dst)
            shutil.move(src, dst)
        os.rmdir(nested)

def validate_docker_compose(project_path, username, container_name):
    compose_file = None
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT max_containers FROM users WHERE username = %s", (username,))
    user_data = cursor.fetchone()
    max_containers = user_data["max_containers"]
    for fname in ["docker-compose.yml", "docker-compose.yaml"]:
    path = os.path.join(project_path, fname)
    if os.path.exists(path):
        compose_file = path
        break
    
    if not compose_file:
        return  "docker-compose.yml file not found"

    try:
        with open(compose_file, "r") as f:
            compose = yaml.safe_load(f)
    except:
        return "docker-compose.yml Syntax Error"

    if "services" not in compose:
        return "No Services Defined in docker-compose.yml"
    
    services = compose["services"]

    value_container = len(services)

    if int(value_container) > (int(max_containers)):
        return f"Exceeded Maximum Container Limit of {max_containers}"

    if len(services) == 0:
        return "No Service Found"

    for service_name, service in services.items():
        if "image" not in service and "build" not in service:
            return f"Service '{service_name}' Must Have Either 'image' or 'build' Defined."
        
        if "ports" in service:
            return f"service '{service_name}' Not Allowed To Map Ports"

        if "volumes" in service:
            paths = service["volumes"]
            for path in paths:
                parts = path.split(":")
                host_path = parts[0]
                if host_path != f"./{username}/{container_name}" and host_path != f"{username}/{container_name}":
                    return f"service '{service_name}' volume paths can only map to '/{username}/{container_name}'"
        
        value_img = service.get("image", "")
        if "mysql" in value_img or "postgres" in value_img or "mariadb" in value_img: 
            return f"service '{service_name}' is Database (Not Allowed) Please Connect Your Database"

        if "labels" in service:
            service["labels"].update({ f"user={username}", f"container={container_name}" })
        else:
            service["labels"] = { f"user={username}", f"container={container_name}" }

        if "networks" in service:
            nets = service["networks"]

            if isinstance(nets, list):
                for n in nets:
                    if n != "lan-net":
                        return f"service '{service_name}' must use lan-net only"

            elif isinstance(nets, dict):
                for n in nets.keys():
                    if n != "lan-net":
                        return f"service '{service_name}' must use lan-net only"

    if "networks" not in compose:
        return "docker-compose.yml must define networks"

    networks = compose["networks"]
    if "lan-net" not in networks:
            return "lan-net network must be defined"

    if not networks["lan-net"].get("external"):
            return "lan-net must be external network"

    return True


@app.route("/api/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    create_db = data.get("create_db")
    conn = None

    try:
        if not username or not email or not password:
            return jsonify({"error": "missing data"}), 400

        hashed = bcrypt.generate_password_hash(password).decode()
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id FROM users WHERE username=%s OR email=%s", (username, email)
        )
        if cursor.fetchone():
            return jsonify({"error": "User Already Exists"}), 409

        if create_db:
            db_name = f"db_{username}"
            cursor.execute(f"CREATE DATABASE {db_name}")
            cursor.execute(f"CREATE USER '{username}'@'%' IDENTIFIED BY '{password}'")
            cursor.execute(f"GRANT ALL PRIVILEGES ON {db_name}.* TO '{username}'@'%'")
            cursor.execute("FLUSH PRIVILEGES")

        cursor.execute(
            "INSERT INTO users (username, email, password, db) VALUES (%s, %s, %s, %s)",
            (username, email, hashed, create_db),
        )
        conn.commit()
        return jsonify({"message": "register success"}), 201
    except Exception as e:
        conn.rollback()
        print("Error:", e)
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()


@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    conn = None

    try:
        if not username or not password:
            return jsonify({"error": "missing data"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
        user = cursor.fetchone()
        if not user:
            return jsonify({"error": "Login Failed Invalid Username or Password"}), 401

        password_hashed = user["password"]
        password_verify = bcrypt.check_password_hash(password_hashed, password)
        if password_verify:
            token = create_access_token(
                identity=str(user["id"]),
                additional_claims={"username": user["username"], "role": user["role"]},
            )

            return (
                jsonify(
                    {"message": "Login Success", "token": token, "role": user["role"]}
                ),
                200,
            )
        else:
            return jsonify({"error": "Login Failed Invalid Username or Password"}), 401

    except Exception as e:
        print("Error:", e)
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()


@app.route("/api/dashboard", methods=["GET"])
@jwt_required()
def dashboard_data():
    try:
        data = get_jwt()
        user_username = data["username"]
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as total FROM users")
        user_total = cursor.fetchone()
        user_total = user_total["total"]
        upload_total = 0
        cursor.execute("SELECT * FROM users WHERE username = %s", (user_username,))
        user_data = cursor.fetchone()
        cursor.execute("SELECT COUNT(req_db) as total FROM users WHERE req_db = 1")
        req_total = cursor.fetchone()
        return (
            jsonify(
                {
                    "username": user_username,
                    "user_total": user_total,
                    "upload_total": upload_total,
                    "email": user_data["email"],
                    "database": user_data["db"],
                    "req_total": req_total["total"],
                }
            ),
            200,
        )

    except Exception as e:
        print("Dashboard Error:", e)
        return jsonify({"error": "Failed to fetch data"}), 500

    finally:
        if conn:
            conn.close()


@app.route("/api/repassword", methods=["POST"])
@jwt_required()
def re_password():
    data = get_jwt()
    username = data["username"]
    password_data = request.json
    password = password_data.get("password")
    new_password = password_data.get("newPassword")
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user_data = cursor.fetchone()

        password_hashed = user_data["password"]
        db = user_data["db"]
        password_verify = bcrypt.check_password_hash(password_hashed, password)
        if not password_verify:
            return jsonify({"error": "Invaid Password Please Try Agian"}), 401

        if db:
            cursor.execute(
                "ALTER USER %s@'%%' IDENTIFIED BY %s", (username, new_password)
            )
            cursor.execute("FLUSH PRIVILEGES")

        hashed = bcrypt.generate_password_hash(new_password).decode()
        cursor.execute(
            "UPDATE users SET password = %s WHERE username = %s",
            (hashed, username),
        )
        conn.commit()
        return jsonify({"message": "Change Password Success"}), 200

    except Exception as e:
        print("Reset Password Error:", e)
        return jsonify({"error": "Failed to fetch data"}), 500
    finally:
        if conn:
            conn.close()


@app.route("/api/maxcontainer", methods=["POST"])
@jwt_required()
def max_container():
    data_token = get_jwt()
    username_token = data_token["username"]
    role_token = data_token["role"]
    data = request.json
    username = data["user"]
    max_containers = data["max_containers"]
    db_mode = data["db_mode"]
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET max_containers = %s WHERE username = %s",
            (max_containers, username),
        )
        db_name = f"db_{username}"

        if role_token == "admin":
            if db_mode:
                cursor.execute(f"CREATE DATABASE IF NOT EXISTS {db_name}")
                cursor.execute(
                    f"CREATE USER IF NOT EXISTS '{username}'@'%' IDENTIFIED BY 'password'"
                )
                cursor.execute(
                    f"GRANT ALL PRIVILEGES ON {db_name}.* TO '{username}'@'%'"
                )
                cursor.execute("FLUSH PRIVILEGES")
                cursor.execute(
                    "UPDATE users SET db = 1 WHERE username = %s", (username,)
                )
                cursor.execute(
                    "UPDATE users SET req_db = 0 WHERE username = %s", (username,)
                )
                conn.commit()
                return (
                    jsonify(
                        {"message": "Updated Containers & Created Database Success"}
                    ),
                    200,
                )
            else:
                cursor.execute(f"DROP DATABASE IF EXISTS {db_name}")
                cursor.execute(f"DROP USER IF EXISTS '{username}'@'%';")
                cursor.execute("FLUSH PRIVILEGES")
                cursor.execute(
                    "UPDATE users SET db = 0 WHERE username = %s", (username,)
                )
                cursor.execute(
                    "UPDATE users SET req_db = 0 WHERE username = %s", (username,)
                )
                conn.commit()
                return jsonify({"message": "Updated Containers Success"}), 200
        else:
            return jsonify({"error": "Permission Denied Admin Only"}), 403
    except Exception as e:
        print("Change Max Container Error:", e)
        return jsonify({"error": "Failed to fetch data"}), 500
    finally:
        if conn:
            conn.close()


@app.route("/api/deluser", methods=["POST"])
@jwt_required()
def deluser():
    data_token = get_jwt()
    username_token = data_token["username"]
    role_token = data_token["role"]
    data = request.json
    username = data["user_del"]
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user_data = cursor.fetchone()
        db_name = f"db_{username}"

        if role_token == "admin" or role_token == "user":
            cursor.execute(f"DROP DATABASE IF EXISTS {db_name}")
            cursor.execute(f"DROP USER IF EXISTS '{username}'@'%';")
            cursor.execute("DELETE FROM users WHERE username = %s", (username,))
            cursor.execute("FLUSH PRIVILEGES")
            conn.commit()
            return jsonify({"message": "Delete Success"}), 200
        else:
            return jsonify({"error": "Permission Denied"}), 403
    except Exception as e:
        print("Change Max Container Error:", e)
        return jsonify({"error": "Failed to fetch data"}), 500
    finally:
        if conn:
            conn.close()


@app.route("/api/users", methods=["GET"])
@jwt_required()
def users_table():
    try:
        data = get_jwt()
        username = data["username"]
        role = data["role"]
        get_role = "user"
        conn = get_db_connection()
        cursor = conn.cursor()

        if role != "admin":
            return jsonify({"error": "Permission Denied Admin Only"}), 403

        cursor.execute("SELECT * FROM users WHERE role = %s", (get_role,))
        users_data = cursor.fetchall()
        return jsonify(users_data), 200

    except Exception as e:
        print("Fetch Data Error:", e)
        return jsonify({"error": "Failed to fetch data"}), 500
    finally:
        if conn:
            conn.close()


@app.route("/api/forgot", methods=["POST"])
def forgot():
    conn = None
    try:
        data = request.json
        username = data["username"]
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user_data = cursor.fetchone()
        if not user_data:
            return jsonify({"error": "Username Not Found"}), 401

        email = user_data["email"]
        otp = f"{random.randint(0,9)}{random.randint(0,9)}{random.randint(0,9)}{random.randint(0,9)}{random.randint(0,9)}{random.randint(0,9)}"
        token = create_access_token(
            identity=user_data["username"],
            additional_claims={
                "otp": otp,
                "role": user_data["role"],
                "email": user_data["email"],
            },
            expires_delta=timedelta(minutes=5),
        )
        mail_otp = Message(
            subject="Adocs",
            recipients=[f"{email}"],
            body=f"OTP : {otp} \n Vaild : 5 minutes",
        )
        mail.send(mail_otp)
        return jsonify({"message": "Get OTP on Your Mail", "token": token}), 200

    except Exception as e:
        print("Fetch Data Error:", e)
        return jsonify({"error": "Failed to fetch data"}), 500
    finally:
        if conn:
            conn.close()


@app.route("/api/forgot_repassword", methods=["POST"])
@jwt_required()
def forgot_repassword():
    conn = None
    try:
        data = request.json
        data_token = get_jwt()
        username_token = get_jwt_identity()
        otp_token = data_token["otp"]
        otp = data["otp"]
        password = data["password"]
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (username_token,))
        user_data = cursor.fetchone()

        if otp_token != otp:
            return jsonify({"error": "Wrong OTP Please Chack Your Mail!"}), 401

        hashed = bcrypt.generate_password_hash(password).decode()
        cursor.execute(
            "UPDATE users SET password = %s WHERE username = %s",
            (hashed, username_token),
        )
        conn.commit()
        return jsonify({"message": "Change Password Success"}), 200

    except Exception as e:
        print("Fetch Data Error:", e)
        return jsonify({"error": "Failed to fetch data"}), 500
    finally:
        if conn:
            conn.close()


@app.route("/api/req_db", methods=["POST"])
@jwt_required()
def req_db():
    conn = None
    try:
        data_token = get_jwt()
        username = data_token["username"]
        data = request.json
        req_db = data["req_db"]
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user_data = cursor.fetchone()
        db_status = user_data["db"]
        req_status = user_data["req_db"]

        if db_status == 1:
            return jsonify({"error": "Already Database Account"}), 401

        if req_status == 1:
            return jsonify({"error": "Request Already Pending"}), 400

        cursor.execute("UPDATE users SET req_db = 1 WHERE username = %s", (username,))
        conn.commit()
        return jsonify({"message": "Request Success Please Wait Admin Approve"}), 200

    except Exception as e:
        print("Fetch Data Error:", e)
        return jsonify({"error": "Failed to fetch data"}), 500
    finally:
        if conn:
            conn.close()


@app.route("/api/upload", methods=["POST"])
@jwt_required()
def upload():
    conn = None
    save_path = os.getenv("BASE_PATH")
    try:
        data_token = get_jwt()
        username = data_token["username"]
        file = request.files["file"]
        container_name = request.form.get("container_name")
        port = request.form.get("port")
        domain = request.form.get("domain")
        project_type = request.form.get("type")
        newfile = request.form.get("newfile")

        user_path = os.path.join(save_path, username)
        os.makedirs(user_path, exist_ok=True)

        filename = secure_filename(file.filename)
        ext = os.path.splitext(filename)[1]
        if not ext == ".zip":
            return jsonify({"error": ".zip File Only"}), 401

        if newfile == "set_new_file":
            new_filename = f"{container_name}{ext}"
            full_path = os.path.join(user_path, new_filename)
            full_path_floder = os.path.join(user_path, container_name)
            if os.path.exists(full_path) or os.path.exists(full_path_floder):
                return jsonify({"error": f"Project '{container_name}' Already Exists Plese Change Container Name"}), 400 
            file.save(full_path)
            try:
                unzip_here(full_path,full_path_floder)
                os.remove(full_path)
                return jsonify({"message": f"Deploy Success Create File {container_name}"}), 200
            except Exception as e:
                print("Fetch Data Error:", e)
                return jsonify({"error": f"Extract failed: {str(e)}"}), 500

        elif newfile == "":
            new_path_filename = f"{container_name}{ext}"
            new_full_path = os.path.join(user_path, new_path_filename)
            new_full_path_floder = os.path.join(user_path, container_name)
            if os.path.exists(new_full_path) or os.path.exists(new_full_path_floder):
                file.save(new_full_path)    
                try:
                    shutil.rmtree(new_full_path_floder)
                    os.makedirs(new_full_path_floder)
                    unzip_here(new_full_path,new_full_path_floder)
                    os.remove(new_full_path)
                    return jsonify({"message": f"Deploy Success By New File {container_name}"}), 200
                except Exception as e:
                    print("Fetch Data Error:", e)
                    return jsonify({"error": f"Extract failed: {str(e)}"}), 500
            else:      
                return jsonify({"error": f"Project '{container_name}' Not Found Cannot Update Plese Check Container Name"}), 400
        else:
            return jsonify({"error": f"Error Can't Save"}), 401

    except Exception as e:
        print("Fetch Data Error:", e)
        return jsonify({"error": "Failed to fetch data"}), 500
    finally:
        if conn:
            conn.close()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
