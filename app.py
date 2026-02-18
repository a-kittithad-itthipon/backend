from flask import Flask, jsonify, request, render_template
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
import subprocess
import requests
import time
from dbutils.pooled_db import PooledDB
from celery.result import AsyncResult 
from tasks import celery_app



        

load_dotenv()
base_path = os.getenv("BASE_PATH")

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

NPM_TOKEN = None
NPM_EXPIRED = 0

POOL = PooledDB(
    creator=pymysql,
    maxconnections=50,  
    mincached=5,
    blocking=True,
    host=os.getenv("DB_HOST"),
    user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASS"),
    database=os.getenv("DB_NAME"),
    cursorclass=pymysql.cursors.DictCursor,
    ping=1,
    connect_timeout=5,
)

def get_db_connection():
    return POOL.connection()

# def get_db_connection():
#     return pymysql.connect(
#         host=os.getenv("DB_HOST"),
#         user=os.getenv("DB_USER"),
#         password=os.getenv("DB_PASS"),
#         database=os.getenv("DB_NAME"),
#         cursorclass=pymysql.cursors.DictCursor,
#     )

def get_npm_token():

    global NPM_TOKEN
    global NPM_EXPIRED

    now = time.time()
    
    if NPM_TOKEN and now < NPM_EXPIRED:
        return NPM_TOKEN

    url = f"{os.getenv('NPM_URL')}/api/tokens"
    payload = {
        "identity": os.getenv("NPM_EMAIL"),
        "secret": os.getenv("NPM_PASSWORD")
    }
    response = requests.post(url, json=payload, verify=False)
    if response.status_code == 200:
        NPM_TOKEN = response.json().get("token")
        NPM_EXPIRED = now + 3600
        return NPM_TOKEN
    return None

def nginx_add_proxy(domain, container_name, port, protocol):
    token = get_npm_token()
    if not token:
        return False, "NPM Auth Failed"

    url = f"{os.getenv('NPM_URL')}/api/nginx/proxy-hosts"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "domain_names": [domain],
        "forward_scheme": protocol,
        "forward_host": container_name,
        "forward_port": int(port),
        "access_list_id": 0,
        "certificate_id": 3,
        "ssl_forced": True,
        "caching_enabled": False,
        "block_exploits": True,
        "advanced_config": "",
        "meta": {},
        "allow_websocket_upgrade": True,
        "http2_support": True,
        "hsts_enabled": True,
        "hsts_subdomains": False
    }

    try:
        response = requests.post(url, json=payload, headers=headers, verify=False, timeout=30)
        
        if response.status_code == 201:
            npm_id = response.json().get("id")
            return True, npm_id
        else:
            return False, response.json().get("error", {}).get("message", "Unknown Error")
    except Exception as e:
        return False, str(e)

def nginx_update_proxy(npm_id, domain, container_name, port, protocol):
    token = get_npm_token()
    if not token: 
        return False, "NPM Auth Failed"

    url = f"{os.getenv('NPM_URL')}/api/nginx/proxy-hosts/{npm_id}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "domain_names": [domain],
        "forward_scheme": protocol,
        "forward_host": container_name,
        "forward_port": int(port),
        "access_list_id": 0,
        "certificate_id": 3,      
        "ssl_forced": True,      
        "caching_enabled": False,
        "block_exploits": True,
        "allow_websocket_upgrade": True,
        "http2_support": True,
        "hsts_enabled": True,
        "hsts_subdomains": False
    }

    try:
        response = requests.put(url, json=payload, headers=headers, verify=False, timeout=30)
        if response.status_code == 200:
            return True, "Proxy Host Updated Successfully"
        else:
            error_msg = response.json().get("error", {}).get("message", "Unknown Error")
            return False, f"NPM Update Failed: {error_msg}"
    except Exception as e:
        return False, f"Connection Error: {str(e)}"

def nginx_delete_proxy(npm_id):
    if not npm_id:
        return True, "No NPM ID"

    token = get_npm_token()
    if not token: 
        return False, "NPM Auth Failed"

    url = f"{os.getenv('NPM_URL')}/api/nginx/proxy-hosts/{npm_id}"
    headers = {
        "Authorization": f"Bearer {token}"
    }

    try:
        response = requests.delete(url, headers=headers, verify=False, timeout=30)
        
        if response.status_code in [200, 204]:
            return True, "Proxy Host Deleted From NPM"
        else:
            error_msg = response.json().get("error", {}).get("message", "Unknown Error")
            return False, f"NPM Delete Failed: {error_msg}"
    except Exception as e:
        return False, f"Connection Error: {str(e)}"

def unzip_here(zip_path, target_dir):
    try:
        target_dir = os.path.abspath(target_dir)
        os.makedirs(target_dir, exist_ok=True)

        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(target_dir)

        time.sleep(0.5)

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
    except Exception as e:
        print(f"Unzip Error: {e}")

def validate_docker_compose(project_path, username, container_name):
    conn = None
    try:
        compose_file = None
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user_data = cursor.fetchone()
        max_containers = user_data["max_containers"]
        current_usage = int(user_data["container"])
        for fname in ["docker-compose.yml", "docker-compose.yaml"]:
            path = os.path.join(project_path, fname)
            if os.path.exists(path):
                compose_file = path
                break
            
        if not compose_file:
            return  "docker-compose.yml file not found" , None , None

        try:
            with open(compose_file, "r") as f:
                compose = yaml.safe_load(f)
        except Exception as e:
            return f"docker-compose.yml Syntax Error: {str(e)}" , None , None

        if "services" not in compose:
            return "No Services Defined in docker-compose.yml" , None , None
        
        services = compose["services"]

        value_container = len(services)
        cursor.execute("SELECT COUNT(*) as count FROM containers WHERE project_path = %s AND owner = %s", (project_path, username))
        container_data = cursor.fetchone()
        old_stack_count = 0

        if not container_data:
            old_stack_count = 0
        else:
            old_stack_count = container_data['count']

        predicted_usage = (current_usage - old_stack_count) + value_container

        if int(predicted_usage) > int(max_containers):
            return f"Quota Exceeded! You have {current_usage}. This stack is {value_container}. Total would be {predicted_usage} (Max: {max_containers})" , None , None

        if len(services) == 0:
            return "No Service Found"

        main_service_found = False

        for service_name, service in services.items():
            if service_name == container_name:
                main_service_found = True

            if "container_name" in service:
                return f"service '{service_name}' cannot define container_name" , None , None

            service["container_name"] = f"{username}_{container_name}_{service_name}"

            if "image" not in service and "build" not in service:
                return f"Service '{service_name}' Must Have Either 'image' or 'build' Defined." , None , None
            
            if "ports" in service:
                return f"service '{service_name}' Not Allowed To Map Ports" , None , None

            if "volumes" in service:
                paths = service["volumes"]
                for path in paths:
                    parts = path.split(":")
                    host_path = parts[0].strip()
                    if ".." in host_path or host_path.startswith("/") or host_path.startswith("~"):
                        return f"Invalid volume path '{host_path}'. Use relative paths starting with './' only." , None , None
        
                    if not host_path.startswith("./"):
                        return f"Volume path '{host_path}' must be relative (start with './')" , None , None
            
            value_img = service.get("image", "")
            if "mysql" in value_img or "postgres" in value_img or "mariadb" in value_img: 
                return f"service '{service_name}' is Database (Not Allowed) Please Connect Your Database" , None , None

            if "labels" in service:
                service["labels"] = {"user": username,"container": container_name}
            else:
                service["labels"] = {"user": username,"container": container_name}

            if "restart" not in service:
                service["restart"] = "unless-stopped"
            else:
                allowed_restarts = ["always", "unless-stopped"]
                if service["restart"] not in allowed_restarts:
                    return f"service '{service_name}' has invalid restart policy. Allowed values are: {', '.join(allowed_restarts)}" , None , None

            if "networks" in service:
                nets = service["networks"]

                if isinstance(nets, list):
                    for n in nets:
                        if n != "lan-net":
                            return f"service '{service_name}' must use lan-net only" , None , None

                elif isinstance(nets, dict):
                    for n in nets.keys():
                        if n != "lan-net":
                            return f"service '{service_name}' must use lan-net only" , None , None

        if not main_service_found:
            return f"Main service '{container_name}' not found in docker-compose.yml. Please ensure the service name matches your main service." , None , None

        if "networks" not in compose:
            return "docker-compose.yml must define networks" , None , None

        networks = compose["networks"]
        if "lan-net" not in networks:
                return "lan-net network must be defined" , None , None

        if not networks["lan-net"].get("external"):
                return "lan-net must be external network" , None , None
        
        try:
            with open(compose_file, "w") as f:
                yaml.safe_dump(compose, f, default_flow_style=False, sort_keys=False)
        except Exception as e:
            return f"Failed to save updated docker-compose file: {str(e)}" , None , None

        return True, value_container, services

    except Exception as e:
        return f"Error processing docker-compose.yml: {str(e)}", None, None
    finally:
        if conn:
            conn.close()

def run_docker_project(project_path, docker_project_name, action):
    down_log_content = (
        f"------------[DOWN LOGS]------------ \n\n"
        f"[CMD]:\n  - None - \n\n\n"
        f"[STDOUT]:\n   - None -\n\n\n"
        f"[STDERR]:\n   - None -\n"
    )
    up_log_content = ""
    full_log_all = ""
    try:
        if action == "UPDATE":
            down_cmd = ["docker", "compose", "-p", docker_project_name, "down", "--remove-orphans"]
            down = subprocess.run(down_cmd, cwd=project_path, capture_output=True, text=True, timeout=300)
            down_log_content = ( 
                f"------------[DOWN LOGS]------------ \n\n"
                f"[CMD]:\n  {down.args}\n\n\n"
                f"[STDOUT]:\n   {down.stdout if down.stdout.strip() else '- None -'}\n\n\n"
                f"[STDERR]:\n   {down.stderr if down.stderr.strip() else '- None -'}\n")

        cmd = ["docker", "compose", "-p", docker_project_name, "up", "-d", "--build"]
        result = subprocess.run(cmd, cwd=project_path, capture_output=True, text=True, timeout=300)
        up_log_content = (
            f"------------[UP LOGS]------------ \n\n"
            f"[CMD]:\n  {result.args}\n\n\n"
            f"[STDOUT]:\n   {result.stdout if result.stdout.strip() else '- None -'}\n\n\n"
            f"[STDERR]:\n   {result.stderr if result.stderr.strip() else '- None -'}\n")
        

        full_log_all = f"{down_log_content} \n\n {up_log_content}"
        if result.returncode == 0:
            return True, full_log_all
        else:
            return False, full_log_all

    except subprocess.TimeoutExpired:
        error_msg = "\n\n[CRITICAL ERROR]: Deployment Timed Out (Process took too long)"
        full_log_all = f"{down_log_content}{up_log_content}{error_msg}"
        return False, full_log_all
    except Exception as e:
        error_msg = f"\n\n[CRITICAL ERROR]: {str(e)}"
        full_log_all = f"{down_log_content}{up_log_content}{error_msg}"
        return False, full_log_all

def update_system_docker(username, value_container, container_name, port, domain, full_log, project_path, project_type, services, domain_name, is_run, action, npm_id):
    conn = None
    status = ""
    full_c_name = ""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE username =  %s",(username,))
        user_data = cursor.fetchone()
        if not user_data:
            return False, f"User '{username}' not found"

        user_id = user_data['id']
        diff_usage = 0

        LIMIT_SIZE = 60000
        if len(full_log) > LIMIT_SIZE:
            head = full_log[:20000]
            tail = full_log[-40000:]
            full_log = f"{head}\n\n REMOVE LOGS: {len(full_log) - LIMIT_SIZE} CHARACTERS \n\n{tail}"

        if not is_run:
            full_c_name = f"{username}_{container_name}_FAILED"
            cursor.execute("INSERT INTO activity_logs (user_id, username, container_name, action, status, details) VALUES (%s, %s, %s, %s, %s, %s)",(user_id, username, full_c_name, action, "FAILED", full_log))
            
            conn.commit()
            return False, "Deployment Failed. Logs saved"

        if action == "UPDATE":
            cursor.execute("SELECT COUNT(*) as count FROM containers WHERE owner=%s AND project_path=%s", (username, project_path))
            result = cursor.fetchone()
            old_stack_count = 0
            if not result:
                old_stack_count = 0
            else:
                old_stack_count = result['count']
                
            diff_usage = int(value_container) - old_stack_count

            cursor.execute("DELETE FROM containers WHERE owner=%s AND project_path=%s",(username, project_path))
        else:
            diff_usage = int(value_container)
        
        cursor.execute("UPDATE users SET container = GREATEST(0, CAST(container AS SIGNED) + %s) WHERE username = %s", (diff_usage, username))

        for service_name in services.keys():
            status = "running"
            full_c_name = f"{username}_{container_name}_{service_name}"
            path = f"{project_path}"
            

            if service_name == container_name:
                cursor.execute("INSERT INTO containers (user_id, owner, npm_id, container_name, status, port_internal, domain, project_path, type, publish) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", (user_id, username, int(npm_id), full_c_name, status, port, domain, path, project_type, True))
            else:
                cursor.execute("INSERT INTO containers (user_id, owner, npm_id, container_name, status, port_internal, domain, project_path, type, publish) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", (user_id, username, None, full_c_name, status, None, "", path, project_type, True))
        
        cursor.execute("INSERT INTO activity_logs (user_id, username, container_name, action, status, details) VALUES (%s, %s, %s, %s, %s, %s)", (user_id, username, full_c_name, action, "SUCCESS", full_log))

        conn.commit()
        return True, "System Updated Successfully"

    except Exception as e:
        if conn:
            conn.rollback()
        print(f"DB Update Error: {e}")
        return False, str(e)
    finally:
        if conn:
            conn.close()

@app.route("/api/task_status/<task_id>", methods=["GET"])
@jwt_required()
def get_task_status(task_id):
    task = celery_app.AsyncResult(task_id)

    if task.state in ['PENDING', 'STARTED']:
        return jsonify({"message": "working"}), 202

    elif task.state == 'SUCCESS':
        result = task.result
        
        if result.get("error"):
            return jsonify({"error": result["error"]}), 500
            
        return jsonify({"message": result["message"]}), 200

    else:
        return jsonify({"error": str(task.result)}), 500


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
            return jsonify({"error": "Username Or Email Already Exists"}), 409

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
    username_add_token = None
    role = None
    password_hashed = None
    user_id = None

    try:
        if not username or not password:
            return jsonify({"error": "missing data"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE email=%s OR username=%s", (username,username))
        user_data = cursor.fetchone()

        if not user_data:
            return jsonify({"error": "Invalid Username Or Email Or Password !"}), 401

        if user_data:
            username_add_token = user_data["username"]
            role = user_data["role"]
            password_hashed = user_data["password"]
            user_id = user_data["id"]

        password_verify = bcrypt.check_password_hash(password_hashed, password)
        if password_verify:
            token = create_access_token(
                identity=str(user_id),
                additional_claims={"username": username_add_token, "role": role},
            )

            return (
                jsonify(
                    {"message": "Login Success", "token": token, "role": role}
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
        cursor.execute("SELECT * FROM users WHERE username = %s", (user_username,))
        user_data = cursor.fetchone()
        cursor.execute("SELECT COUNT(req_db) as total FROM users WHERE req_db = 1")
        req_total = cursor.fetchone()

        action = "DEPLOY"
        cursor.execute("SELECT COUNT(*) as total FROM activity_logs WHERE action = 'DEPLOY'")
        upload_total = cursor.fetchone()

        cursor.execute("SELECT COUNT(*) as total FROM activity_logs WHERE action = 'DEPLOY' AND username = %s", (user_username,))
        user_upload_total = cursor.fetchone()

        return (
            jsonify(
                {
                    "username": user_username,
                    "user_total": user_total,
                    "upload_total": upload_total["total"],
                    "email": user_data["email"],
                    "database": user_data["db"],
                    "req_total": req_total["total"],
                    "user_upload_total": user_upload_total["total"],
                    "max_containers": user_data["max_containers"],
                    "container_used": user_data["container"],
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
        
        container_count = int(max_containers)
    
        if container_count < 5 or container_count > 10:
            return jsonify({"error": "Out of Range Must be between 5 and 10"}), 400
        
        cursor.execute("UPDATE users SET max_containers = %s WHERE username = %s",(max_containers, username),)
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
                        {"message": "Updated Containers or Created Database Success"}
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
    id_users = get_jwt_identity()
    username_token = data_token["username"]
    role_token = data_token["role"]
    data = request.json
    username = data["user_del"]
    conn = None
    n = 0

    if role_token != "admin" and username_token != username:
        return jsonify({"error": "Permission Denied"}), 403
        
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user_data = cursor.fetchone()
        
        if not user_data:
            return jsonify({"error": "User Not Found"}), 404
        
        all_docker_logs = [f"[DELETE]:\n USERNAME: {username} \n ID: {user_data["id"]} \n\n\n"]
        db_name = f"db_{username}"

        cursor.execute("SELECT * FROM users WHERE status = %s AND username = %s", ("DELETING", username))  
        is_processing = cursor.fetchone()
        if is_processing and is_processing["status"] == "DELETING":
            return jsonify({"message": "This user is already being deleted. Please wait."}), 429

        cursor.execute("SELECT * FROM containers WHERE owner = %s", (username,))
        container_user_data = cursor.fetchall()
        
        full_log = "\n".join(all_docker_logs)
        cursor.execute("UPDATE users SET status = 'DELETING' WHERE username = %s", (username,))
        cursor.execute("INSERT INTO activity_logs (user_id, username, container_name, action, status, details) VALUES (%s, %s, %s, %s, %s, %s)", (id_users, username_token, f"ACCOUNT: {username}", "DELETE", "PENDING", full_log))
        conn.commit()

        log_id = cursor.lastrowid
        from tasks import docker_deluser
        task = docker_deluser.delay(username, container_user_data, db_name, all_docker_logs, id_users, username_token, log_id)

        return jsonify({"message": "Delete Success", "task_id": task.id}), 200
    except Exception as e:
        if conn:
            conn.rollback()
        print("Fetch Data Error:", e)
        return jsonify({"error": "Failed to fetch data"}), 500
    finally:
        if conn:
            conn.close()

@app.route("/api/users", methods=["GET"])
@jwt_required()
def users_table():
    conn = None
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

@app.route("/api/logs", methods=["GET"])
@jwt_required()
def logs():
    conn = None
    try:
        data = get_jwt()
        username = data["username"]
        role = data["role"]
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if role == "admin":
            cursor.execute("SELECT * FROM activity_logs ORDER BY created_at DESC LIMIT 150")
            logs_data = cursor.fetchall()
            if not logs_data:
                return jsonify({"error": "No Logs Data"}) , 401
            return jsonify(logs_data) , 200
        elif role == "user":
            cursor.execute("SELECT * FROM activity_logs WHERE username = %s ORDER BY created_at DESC LIMIT 50",(username,))
            logs_data = cursor.fetchall()
            if not logs_data:
                return jsonify({"error": "No Logs Data"}) , 401
            return jsonify(logs_data) , 200
        else:
            return jsonify({"error": "Fetch Logs Error"}) , 401
    except Exception as e:
        print("Fetch Data Error:", e)
        return jsonify({"error": "Failed to fetch data"}), 500
    finally:
        if conn:
            conn.close()

@app.route("/api/container_data", methods=["GET"])
@jwt_required()
def container_data():
    conn = None
    try:
        data = get_jwt()
        username = data["username"]
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM containers WHERE owner = %s",(username,))
        containers_data = cursor.fetchall()

        if not containers_data:
            return jsonify({"error": "No Containers Data"}) , 401
        
        return jsonify(containers_data) , 200

    except Exception as e:
        print("Fetch Data Error:", e)
        return jsonify({"error": "Failed to fetch data"}), 500
    finally:
        if conn:
            conn.close()

@app.route("/api/active_site", methods=["GET"])
def active_site():
    conn = None
    try:
        username = "admin"
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM containers WHERE owner != %s AND publish = 1 ORDER BY updated_at DESC",(username,))
        system_data = cursor.fetchall()

        if not system_data:
            return jsonify({"error": "No System Data"}) , 401
        
        return jsonify(system_data) , 200

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

        cursor.execute("SELECT * FROM users WHERE username = %s OR email = %s", (username, username))
        user_data = cursor.fetchone()
        if not user_data:
            return jsonify({"error": "Username Or Email Not Found"}), 401

        email = user_data["email"]
        username_send = user_data["username"]
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
        )
        mail_otp.html = render_template("/mail.html", otp=otp, username=username_send)
        
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
        
        if user_data["db"] == 1:
            cursor.execute("ALTER USER %s@'%%' IDENTIFIED BY %s", (username_token, password))
            cursor.execute("FLUSH PRIVILEGES")
        
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


@app.route("/api/portupdate", methods=["POST"])
@jwt_required()
def port_update():
    conn = None
    try:
        data_token = get_jwt()
        username = data_token["username"]
        data = request.json
        port = data["port"]
        container_name = data["containerName"]
        protocol = data["type"]
        pub = data["pub"]
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM containers WHERE container_name = %s", (container_name,))
        user_data = cursor.fetchone()
        domain = user_data["domain"]
        port_internal = user_data["port_internal"]
        forward_scheme = user_data["forward_scheme"]


        if not domain:
            try:
                if port == "" or port is None:
                    cursor.execute("UPDATE containers SET port_internal = NULL, publish = %s WHERE container_name = %s AND owner = %s", (pub, container_name, username))
                else:
                    cursor.execute("UPDATE containers SET port_internal = %s, publish = %s WHERE container_name = %s AND owner = %s", (port, pub, container_name, username))
                conn.commit()
                return jsonify({"message": "Update Port Success"}) , 201
            except Exception as e:
                if conn:
                    conn.rollback()
                print("Fetch Data Error:", e)
                return jsonify({"error": "Failed to fetch data"}), 500
            
        elif domain:
            if port_internal == port and forward_scheme == protocol or port is None or port == "":
                if port == "" or port is None:
                    port = int(port_internal)
                try:
                    cursor.execute("UPDATE containers SET publish = %s WHERE container_name = %s", (pub, container_name))
                    conn.commit()
                    return jsonify({"message": "Update Publish Status Success"}), 201
                except Exception as e:
                    return jsonify({"error": "Failed to Update Publish Status"}), 500
            else:                
                if port == "" or port is None:
                    port = int(port_internal)
                try:
                    status , msg_npm = nginx_update_proxy(user_data["npm_id"], domain, user_data["container_name"], port, protocol)
                    if status:
                        cursor.execute("UPDATE containers SET port_internal = %s, forward_scheme = %s, 	publish = %s WHERE container_name = %s", (port, protocol, pub, container_name))
                        conn.commit()
                        return jsonify({"message": "Update Port Proxy Host and Publish Status Success"}), 201
                    else:
                        return jsonify({"error": f"NPM Update Failed: {msg_npm}"}), 500
                    
                except Exception as e:
                    if conn:
                        conn.rollback()
                    print("Internal Error:", e)
                    return jsonify({"error": "Failed to update proxy or database"}), 500

        else:
            return jsonify({"error": "Data Error"}) , 400

    except Exception as e:
        if conn:
            conn.rollback()
        print("Fetch Data Error:", e)
        return jsonify({"error": "Failed to fetch data"}), 500
    finally:
        if conn:
            conn.close()


@app.route("/api/delstack", methods=["POST"])
@jwt_required()
def del_stack():
    conn = None
    container_list = []
    result = None
    try:
        data_token = get_jwt()
        username = data_token["username"]
        data = request.json
        project_path = data["stack"]
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user_data = cursor.fetchone()
        user_id = user_data['id']
        container_value = int(user_data['container'])

        if not user_data:
            return jsonify({"error": "Users Data Not Found"}), 400

        cursor.execute("SELECT * FROM containers WHERE project_path = %s AND owner = %s", (project_path,username))
        container_user_data = cursor.fetchall()
        if not container_user_data:
            return jsonify({"error": "No Stack Found"}), 404

        cursor.execute("SELECT * FROM containers WHERE project_path = %s AND owner = %s AND status = %s", (project_path,username,"pending"))
        pending_data = cursor.fetchall()
        if pending_data:
            return jsonify({"error": "This Stack is already being deleted. Please wait."}), 429
        
        folder_name = os.path.basename(project_path) 
        docker_project_name = f"{username}_{folder_name}"

        for container in container_user_data:
            container_list.append(container["container_name"])

        full_c_name = f"STACK : {folder_name}"
        full_log = (
            f"------------[DELETE STACK]------------ \n\n"
            f"[CMD]:\n  {docker_project_name}\n\n\n"
            f"[STDOUT]:\n   - PENDING -\n\n\n"
            f"[STDERR]:\n   - PENDING -\n\n\n"
            f"[NPM]:\n   - PENDING -\n\n\n"
            f"[CONTAINER NAME]:\n  -PENDING- \n"
            )
        
        cursor.execute("UPDATE containers SET status = %s WHERE project_path = %s AND owner = %s", ("pending", project_path, username))
        cursor.execute("INSERT INTO activity_logs (user_id, username, container_name, action, status, details) VALUES (%s, %s, %s, %s, %s, %s)", (user_id, username, full_c_name, "DELETE", "PENDING", full_log))      
        conn.commit()
        log_id = cursor.lastrowid

        from tasks import docker_delstack
        task = docker_delstack.delay(project_path, docker_project_name, folder_name, username, user_id, container_list, container_value, container_user_data, log_id)

        return jsonify({"message": "Stack deleted successfully", "task_id": task.id}), 200
    
    except Exception as e:
        if conn:
            conn.rollback()
        print("Fetch Data Error:", e)
        return jsonify({"error": "Failed to fetch data"}), 500
    finally:
        if conn:
            conn.close()

@app.route("/api/upload", methods=["POST"])
@jwt_required()
def upload():
    conn = None
    raw_save_path = os.getenv("BASE_PATH")
    if not raw_save_path:
        return jsonify({"error": "BASE_PATH not set in .env"}), 500
    path_to_clean_folder = None
    path_to_clean_zip = None
    task_started = False
    save_path = os.path.normpath(raw_save_path)

    try:
        data_token = get_jwt()
        username = data_token["username"]
        file = request.files["file"]
        raw_container_name = request.form.get("container_name")
        container_name = secure_filename(raw_container_name)
        port = request.form.get("port")
        domain_name = request.form.get("domain")
        domain = f"{domain_name}.addp.site"
        project_type = request.form.get("type")
        newfile = request.form.get("newfile")
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM containers WHERE domain = %s",(domain,))
        domain_exists = cursor.fetchone()
        
        if not domain_exists:
            domain_exists = None
        
        if newfile == "set_new_file" and domain_exists is not None:
            return jsonify({"error": "Domain Already Exists Please Use Other Domain"}), 400


        user_path = os.path.abspath(os.path.join(save_path, username))
        os.makedirs(user_path, exist_ok=True)


        filename = secure_filename(file.filename)
        ext = os.path.splitext(filename)[1]
        if not ext == ".zip":
            return jsonify({"error": ".zip File Only"}), 401

        if newfile == "set_new_file":
            action = "DEPLOY"
            new_filename = f"{container_name}{ext}"
            full_path = os.path.abspath(os.path.join(user_path, new_filename))
            full_path_floder = os.path.abspath(os.path.join(user_path, container_name))

            path_to_clean_zip = full_path
            path_to_clean_folder = full_path_floder

            if os.path.exists(full_path) or os.path.exists(full_path_floder):
                return jsonify({"error": f"Project '{container_name}' Already Exists Plese Change Service Name"}), 400 

            file.save(full_path)

            try:
                unzip_here(full_path,full_path_floder)
                
                compose = os.path.join(full_path_floder, "docker-compose.yml")
                if not os.path.exists(compose):
                    return jsonify({"error": f"Project '{container_name}' Not Found Cannot Deploy Plese Check Service Name"}), 400

                validate_result, value_container, services = validate_docker_compose(full_path_floder, username, container_name)

                if validate_result != True:
                    shutil.rmtree(full_path_floder)
                    os.remove(full_path)
                    return jsonify({"error": f"docker-compose.yml Validation Failed: {validate_result}"}), 400

                
                docker_project_name = f"{username}_{container_name}"

                from tasks import docker_deploy
                task = docker_deploy.delay(full_path, full_path_floder, docker_project_name, action, username, container_name, port, domain, project_type, services, domain_name, value_container)
                task_started = True
                
                return jsonify({"message": f"Deploying Project '{container_name}' Wait for Background Task", "task_id": task.id}), 200

            except Exception as e:
                print("Fetch Data Error:", e)
                
                if full_path_floder and os.path.exists(full_path_floder):
                    shutil.rmtree(full_path_floder)
                
                if full_path and os.path.exists(full_path):
                    os.remove(full_path)

                return jsonify({"error": f"Extract or Deploy failed: {str(e)}"}), 500

        elif newfile == "":
            action = "UPDATE"
            
            if domain_exists is None:
                return jsonify({"error": f"Domain '{domain}' not found in system"}), 404
                
            if domain_exists["domain"] != domain:
                return jsonify({"error": f"Your Input Domain is {domain} Not Match Your System Domain {domain_exists['domain']} "}) , 400

            new_path_filename = f"{container_name}{ext}"
            new_full_path = os.path.join(user_path, new_path_filename)
            new_full_path_floder = os.path.join(user_path, container_name)
            path_to_clean_zip = new_full_path
            path_to_clean_folder = new_full_path_floder
            
            compose = os.path.join(new_full_path_floder, "docker-compose.yml")
            if not os.path.exists(compose):
                return jsonify({"error": f"Project '{container_name}' Not Found Cannot Update Plese Check Service Name"}), 400

            if os.path.exists(new_full_path) or os.path.exists(new_full_path_floder):
                file.save(new_full_path)    
                try:
                    shutil.rmtree(new_full_path_floder)
                    os.makedirs(new_full_path_floder)
                    unzip_here(new_full_path,new_full_path_floder)

                    if not os.path.exists(os.path.join(new_full_path_floder, "docker-compose.yml")):
                        return jsonify({"error": "docker-compose.yml Not Found in Update Zip"}), 400

                    validate_result, value_container, services = validate_docker_compose(new_full_path_floder, username, container_name)
                    if validate_result != True:
                        shutil.rmtree(new_full_path_floder)
                        os.remove(new_full_path)
                        return jsonify({"error": f"docker-compose.yml Validation Failed: {validate_result}"}), 400

                    docker_project_name = f"{username}_{container_name}"
                    npm_id = domain_exists["npm_id"]

                    from tasks import docker_update
                    task = docker_update.delay(new_full_path, new_full_path_floder, docker_project_name, action, username, container_name, port, domain, project_type, services, domain_name, npm_id, value_container)
                    task_started = True

                    return jsonify({"message": f"Updating Project '{container_name}' Wait for Background Task", "task_id": task.id}), 200

                except Exception as e:
                    print("Fetch Data Error:", e)
                    if new_full_path_floder and os.path.exists(new_full_path_floder):
                        shutil.rmtree(new_full_path_floder)
                
                    if new_full_path and os.path.exists(new_full_path):
                        os.remove(new_full_path)

                    return jsonify({"error": f"Extract or Deploy failed: {str(e)}"}), 500
            else:      
                return jsonify({"error": f"Project '{container_name}' Not Found Cannot Update Plese Check Container Name"}), 400
        else:
            return jsonify({"error": f"Error Can't Save"}), 401

    except Exception as e:
        print(f"Deployment Error: {e}")
        
        if conn: 
            conn.rollback()

        if not task_started:
            if path_to_clean_folder and os.path.exists(path_to_clean_folder):
                try:
                    shutil.rmtree(path_to_clean_folder)
                except Exception as ex:
                    print(f"Failed to cleanup folder: {ex}")

            if path_to_clean_zip and os.path.exists(path_to_clean_zip):
                try:
                    os.remove(path_to_clean_zip)
                except Exception as ex:
                    print(f"Failed to cleanup zip: {ex}")
                
        return jsonify({"error": "Failed to fetch data"}), 500
    finally:
        if conn:
            conn.close()

@app.route("/api/status_container", methods=["POST"])
@jwt_required()
def status_container():
    conn = None
    cmd = []
    result_action = ""
    try:
        data_token = get_jwt()
        username = data_token["username"]
        data = request.json
        project_path = data.get("stack")
        action = data.get("status")

        if not project_path or not action:
            return jsonify({"error": "Missing stack path or status"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        folder_name = os.path.basename(project_path)
        docker_project_name = f"{username}_{folder_name}"

        if action == "running":
            cmd = ["docker", "compose", "-p", docker_project_name, "stop"]
            result_action = "stopped"
        elif action == "stopped":
            cmd = ["docker", "compose", "-p", docker_project_name, "up", "-d"]
            result_action = "running"
        else:
            return jsonify({"error": "Invalid status action"}), 400

        cursor.execute("SELECT * FROM containers WHERE project_path = %s AND owner = %s",(project_path, username))
        containers = cursor.fetchall()
        
        if not containers:
            return jsonify({"error": "Stack Not Found or Permission Denied"}), 404


        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user_data = cursor.fetchone()
        user_id = user_data['id']

        log_content = (
            f"------------[{result_action.upper()} LOGS]------------ \n\n"
            f"[CMD]:\n  {cmd}\n\n\n"
            f"[STDOUT]:\n   - PENDING -\n\n\n"
            f"[STDERR]:\n   - PENDING -\n"
        )
        full_c_name = f"STACK : {folder_name}"

        cursor.execute("UPDATE containers SET status = %s WHERE project_path = %s AND owner = %s",("pending", project_path, username))
        cursor.execute("INSERT INTO activity_logs (user_id, username, container_name, action, status, details) VALUES (%s, %s, %s, %s, %s, %s)", (user_id, username, full_c_name, result_action.upper(), "PENDING", log_content))
        log_id = cursor.lastrowid

        conn.commit()

        from tasks import docker_start_stop
        task = docker_start_stop.delay(result_action, folder_name, project_path, docker_project_name, cmd, username, log_id)

        return jsonify({"message": f"Container {result_action} Pending", "task_id": task.id }), 200

    except Exception as e:
        if conn:
            conn.rollback()
        print(f"Status Change Error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
