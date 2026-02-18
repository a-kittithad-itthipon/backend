from celery import Celery
import subprocess
import pymysql
import os
from dotenv import load_dotenv
import requests
import shutil
import time
from dbutils.pooled_db import PooledDB

basedir = os.path.abspath(os.path.dirname(__file__))
env_path = os.path.join(basedir, '.env')
load_dotenv(env_path)

celery_app = Celery('tasks', broker='redis://localhost:6379/1', backend='redis://localhost:6379/2')
# celery_app = Celery('tasks', broker='redis://redis-broker:6379/1', backend='redis://redis-broker:6379/2')

def get_db_connection():
    return pymysql.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASS"),
        database=os.getenv("DB_NAME"),
        cursorclass=pymysql.cursors.DictCursor,
    )


NPM_TOKEN = None
NPM_EXPIRED = 0

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
            down = subprocess.run(down_cmd, cwd=project_path, capture_output=True, text=True, timeout=300, encoding='utf-8',errors='replace')
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

@celery_app.task(bind=True)
def docker_start_stop(self, result_action, folder_name, project_path, docker_project_name, cmd, username, log_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user_data = cursor.fetchone()
    user_id = user_data['id']

    try:
        result = subprocess.run(cmd, cwd=project_path, capture_output=True, text=True, timeout=300)
        
        log_content = (
            f"------------[{result_action.upper()} LOGS]------------ \n\n"
            f"[CMD]:\n  {result.args}\n\n\n"
            f"[STDOUT]:\n   {result.stdout if result.stdout.strip() else '- None -'}\n\n\n"
            f"[STDERR]:\n   {result.stderr if result.stderr.strip() else '- None -'}\n"
        )

        if result.returncode != 0:
            cursor.execute("UPDATE containers SET status = %s WHERE project_path = %s AND owner = %s",("failed", project_path, username))
            cursor.execute("UPDATE activity_logs SET status = %s, details = %s WHERE id = %s", ("FAILED", log_content, log_id))
            conn.commit()
            return {"error": f"Error: Deployment Failed\n\n{log_content}"}

        cursor.execute("UPDATE containers SET status = %s WHERE project_path = %s AND owner = %s",(result_action, project_path, username))
        full_c_name = f"STACK : {folder_name}"
        cursor.execute("UPDATE activity_logs SET status = %s, details = %s WHERE id = %s", ("SUCCESS", log_content, log_id))
        conn.commit()

        return {"message": f"Container {result_action} successfully"}

    except subprocess.TimeoutExpired:
        cursor.execute("UPDATE containers SET status = %s WHERE project_path = %s AND owner = %s",("failed", project_path, username))
        conn.commit()
        return {"error": "Error: Deployment Timed Out (Process took too long)"}
    except Exception as ex:
        cursor.execute("UPDATE containers SET status = %s WHERE project_path = %s AND owner = %s",("failed", project_path, username))
        conn.commit()
        return {"error": f"Error: {str(ex)}"}
    finally:
        if conn:
            conn.close()


@celery_app.task(bind=True)
def docker_delstack(self, project_path, docker_project_name, folder_name, username, user_id, container_list, container_value, container_user_data, log_id):
    msg_npm = "- None -"
    npm_logs = []
    conn = None

    try:

        conn = get_db_connection()
        cursor = conn.cursor()
        result = None

        for container in container_user_data:
            if container['npm_id']:
                status , msg_npm = nginx_delete_proxy(container['npm_id'])
            npm_logs.append(f"{container['domain']}: {msg_npm}")

        if project_path and os.path.exists(project_path):
            try:
                cmd_del = ["docker", "compose", "-p", docker_project_name, "down", "--remove-orphans"]
                result = subprocess.run(cmd_del, cwd=project_path, capture_output=True, text=True, timeout=300)
            except Exception as e:
                print(f"Docker/File Cleanup Error: {e}")
                return {"error": f"Docker/File Cleanup Error: {str(e)}"}
            
        full_c_name = f"STACK : {folder_name}"
        log_str_npm = "\n".join(npm_logs)
        log_str_container = "\n".join(container_list)
        full_log = (
            f"------------[DELETE STACK]------------ \n\n"
            f"[CMD]:\n  {result.args if result else 'N/A'}\n\n\n"
            f"[STDOUT]:\n   {result.stdout if result.stdout.strip() else '- None -'}\n\n\n"
            f"[STDERR]:\n   {result.stderr if result.stderr.strip() else '- None -'}\n\n\n"
            f"[NPM]:\n   {log_str_npm}\n\n\n"
            f"[CONTAINER NAME]:\n  {log_str_container}\n"
            )

        if result.returncode != 0:
            cursor.execute("UPDATE activity_logs SET status = %s, details = %s WHERE id = %s", ("FAILED", full_log, log_id))
            conn.commit()
            return {"error": f"Error: Stack Deletion Failed\n\n{full_log}"}

        cursor.execute("DELETE FROM containers WHERE project_path = %s AND owner = %s", (project_path, username))
        deleted_count = len(container_list)
        if deleted_count > 0:
            cursor.execute("UPDATE users SET container = GREATEST(0, CAST(container AS SIGNED) - %s) WHERE username = %s", (deleted_count, username))

        cursor.execute("UPDATE activity_logs SET status = %s, details = %s WHERE id = %s", ("SUCCESS", full_log, log_id))
        conn.commit()

        if project_path and os.path.exists(project_path):
            if result and result.returncode == 0:
                try:
                    shutil.rmtree(project_path)
                except Exception as e:
                    print(f"Warning: Failed to delete folder {project_path}: {e}")

        return {"message": "Stack deleted successfully"}
    except Exception as e:
        if conn:
            conn.rollback()
            print(f"Error deleting stack '{folder_name}': {e}")

        try:
            if conn and log_id:
                err_msg = f"System Error: {str(e)}"
                cursor.execute("UPDATE activity_logs SET status = %s, details = %s WHERE id = %s", ("FAILED", err_msg, log_id))
                conn.commit()
        except:
            pass

        print(f"Error deleting stack '{folder_name}': {e}")
        return {"error": f"Error deleting stack '{folder_name}': {str(e)}"}
    finally:
        if conn:
            conn.close()

@celery_app.task(bind=True)
def docker_deluser(self, username, container_user_data, db_name, all_docker_logs, id_users, username_token, log_id):
    processed_paths = set()
    n = 0
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        for container in container_user_data:
            c_name = container['container_name']
            project_path = container['project_path']
            container_owner = container['owner']

            folder_name = os.path.basename(project_path)
            docker_project_name = f"{container_owner}_{folder_name}"

            msg_npm = "- None -"
            if container['npm_id']:
                status, msg_npm = nginx_delete_proxy(container['npm_id'])
            

            if project_path and os.path.exists(project_path) and project_path not in processed_paths:
                try:
                    cmd_del = ["docker", "compose", "-p", docker_project_name, "down", "--remove-orphans"]
                    result = subprocess.run(cmd_del, cwd=project_path, capture_output=True, text=True, timeout=300)

                    all_docker_logs.append(
                        f"------------[DELETE {n+1}]------------ \n\n"
                        f"[CMD]:\n  {result.args}\n\n\n"
                        f"[STDOUT]:\n   {result.stdout if result.stdout.strip() else '- None -'}\n\n\n"
                        f"[STDERR]:\n   {result.stderr if result.stderr.strip() else '- None -'}\n\n\n"
                        f"[NPM]:\n   {msg_npm}\n\n\n"
                        f"[CONTAINER NAME]:\n  {c_name if c_name else '- None -'}\n"
                        )
                    n+=1

                    shutil.rmtree(container['project_path'])
                    processed_paths.add(project_path)

                except Exception as ex:
                    print(f"Docker Down Error for {project_path}: {ex}")

        full_log = "\n".join(all_docker_logs)
        if log_id:
             cursor.execute("UPDATE activity_logs SET status = %s, details = %s WHERE id = %s", ("SUCCESS", full_log, log_id))
        else:
             cursor.execute("INSERT INTO activity_logs (user_id, username, container_name, action, status, details) VALUES (%s, %s, %s, %s, %s, %s)", (id_users, username_token, f"ACCOUNT: {username}", "DELETE", "SUCCESS", full_log))
        
        cursor.execute("DELETE FROM containers WHERE owner = %s", (username,))
        user_root_path = os.path.join(os.getenv("BASE_PATH"), username)
        if os.path.exists(user_root_path):
            shutil.rmtree(user_root_path)

        cursor.execute(f"DROP DATABASE IF EXISTS {db_name}")
        cursor.execute(f"DROP USER IF EXISTS '{username}'@'%';")
        cursor.execute("DELETE FROM users WHERE username = %s", (username,))
        cursor.execute("FLUSH PRIVILEGES")

        conn.commit()
        return {"message": f"User '{username}' and all associated data deleted successfully"}
    except Exception as e:
        if conn:
            conn.rollback()
        print(f"Error deleting user '{username}': {e}")
        return {"error": f"Error deleting user '{username}': {str(e)}"}
    finally:
        if conn:
            conn.close()

@celery_app.task(bind=True)
def docker_deploy(self, full_path, full_path_floder, docker_project_name, action, username, container_name, port, domain, project_type, services, domain_name, value_container):
    try:
        is_run , logs = run_docker_project(full_path_floder, docker_project_name, action)
        if not is_run:
            shutil.rmtree(full_path_floder)
            os.remove(full_path)
            logs += "\n\n[CRITICAL ERROR]: Deployment Failed"
            result_stat, result_update =  update_system_docker(username, value_container, container_name, port, domain, logs, full_path_floder, project_type, services, domain_name, False, action, None)
            return {"error": f"Deployment Failed: \n\n{logs}"}

        full_container_name = services[container_name]["container_name"]
        status , msg_npm = nginx_add_proxy(domain, full_container_name, port, "http")
        if not status:
            shutil.rmtree(full_path_floder)
            os.remove(full_path)
            logs += f"\n\n[CRITICAL ERROR]: NPM Proxy Creation Failed: {msg_npm}"
            result_stat, result_update =  update_system_docker(username, value_container, container_name, port, domain, logs, full_path_floder, project_type, services, domain_name, False, action, msg_npm)
            return {"error": f"NPM Proxy Creation Failed: {msg_npm}"}

        result_stat, result_update =  update_system_docker(username, value_container, container_name, port, domain, logs, full_path_floder, project_type, services, domain_name, is_run, action, msg_npm)
        if not result_stat:
            try:
                subprocess.run(["docker", "compose", "-p", docker_project_name, "down"], cwd=full_path_floder, timeout=60)
            except:
                pass
            shutil.rmtree(full_path_floder)
            os.remove(full_path)
            return {"error": f"DB Save Failed: {result_update}"}

        os.remove(full_path)
        path_to_clean_folder = None
        path_to_clean_zip = None

        return {"message": f"Deploy Success Create File {container_name} and {result_update}"}

    except Exception as e:
        print(f"Deployment Error: {e}")
        try:
             update_system_docker(username, value_container, container_name, port, domain, f"Deployment Error: {str(e)}", new_full_path_floder, project_type, services, domain_name, False, action, None)
        except:
            pass
        return {"error": f"Deployment Error: {str(e)}"}

@celery_app.task(bind=True)
def docker_update(self, new_full_path, new_full_path_floder, docker_project_name, action, username, container_name, port, domain, project_type, services, domain_name, npm_id, value_container):
    try:
        is_run , logs = run_docker_project(new_full_path_floder,docker_project_name, action)
        if not is_run:
            try:
                subprocess.run(["docker", "compose", "-p", docker_project_name, "down", "--remove-orphans"], cwd=new_full_path_floder, capture_output=True, timeout=30)
            except:
                pass

            shutil.rmtree(new_full_path_floder)
            os.remove(new_full_path)
            logs += "\n\n[CRITICAL ERROR]: Deployment Failed"
            result_stat, result_update =  update_system_docker(username, value_container, container_name, port, domain, logs, new_full_path_floder, project_type, services, domain_name, False, action, npm_id)
            return {"error": f"Deployment Failed: \n\n{logs}"}

        status , msg_npm = nginx_update_proxy(npm_id, domain, services[container_name]["container_name"], port, "http")
        if not status:
            shutil.rmtree(new_full_path_floder)
            os.remove(new_full_path)
            logs += f"\n\n[CRITICAL ERROR]: NPM Proxy Update Failed: {msg_npm}"
            result_stat, result_update =  update_system_docker(username, value_container, container_name, port, domain, logs, new_full_path_floder, project_type, services, domain_name, False, action, npm_id)
            return {"error": f"NPM Proxy Update Failed: {msg_npm}"}

        result_stat, result_update =  update_system_docker(username, value_container, container_name, port, domain, logs, new_full_path_floder, project_type, services, domain_name, is_run, action, npm_id)
        if not result_stat:
            try:
                subprocess.run(["docker", "compose", "-p", docker_project_name, "down"], cwd=new_full_path_floder, timeout=60)
            except:
                pass
            shutil.rmtree(new_full_path_floder)
            os.remove(new_full_path)
            return {"error": f"DB Save Failed: {result_update}"}

        os.remove(new_full_path)
        path_to_clean_folder = None
        path_to_clean_zip = None

        return {"message": f"Deploy Success By New File {container_name} , {result_update} and {msg_npm}"}

    except Exception as e:
        print(f"Deployment Error: {e}")
        try:
             update_system_docker(username, value_container, container_name, port, domain, f"Deployment Error: {str(e)}", new_full_path_floder, project_type, services, domain_name, False, action, None)
        except:
            pass
        return {"error": f"Deployment Error: {str(e)}"}