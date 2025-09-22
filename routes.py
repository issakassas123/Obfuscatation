from functools import wraps
from json import load
import secrets
import sqlite3
import string
from flask import current_app, jsonify, render_template, request, abort

from app.db_configuration import create_table

app=current_app
@app.before_request
def check_ip():
 t = get_firewall_status()
 if t==1: 
    ip = get_client_ip()
    if not ip:
        return jsonify({"error": "No IP provided"}), 400

    trusted_ips = get_trusted_ips()
    if ip  not in trusted_ips:
        return abort(403)
def get_trusted_ips():
    try:
        conn = sqlite3.connect("db\vault.db")  # Adjust path as needed
        cursor = conn.cursor()
        cursor.execute('SELECT ip FROM trusted_ip;')
        trusted_ips = {row[0] for row in cursor.fetchall()}  # Using a set for O(1) lookup
        cursor.close()
        conn.close()
        return trusted_ips
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error: {e}")
        return None
    

def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get("X-API-KEY")
        if not api_key or not is_valid_token(api_key):
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)

    return decorated_function


def is_valid_token(token):
    try:
        print(token)
        conn = sqlite3.connect("db\vault.db")
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM tokens WHERE token=?", (token,))
        result = cursor.fetchone()
        conn.close()
	
        return result is not None

    except sqlite3.Error as e:
        print("SQLite error:", e)
        return False



def execute_query(query, values=None):
    try:
        # Connect to the SQLite database
        conn = sqlite3.connect("db\vault.db")  # Ensure the path is correct and exists
        cursor = conn.cursor()

        # Execute the query with parameters if provided
        if values:
            cursor.execute(query, values)
        else:
            cursor.execute(query)

        # Commit the transaction to make the changes permanent
        conn.commit()

        # Fetch all results if it's a SELECT query
        if query.strip().upper().startswith("SELECT"):
            results = cursor.fetchall()
            return jsonify({"results": results})


        # Close the database connection
        conn.close()

        return jsonify({"message": "Query executed successfully"})

    except sqlite3.Error as e:
        print("SQLite error:", e)
        return jsonify({"error": "Database error"})

    except Exception as ex:
        print("Exception:", ex)
        return jsonify({"error": "Internal server error"})

@require_api_key
@app.route('/api/trusted_ips', methods=['GET'])
def get_trusted_ips_json():
    trusted_ips = get_trusted_ips()
    if trusted_ips is None:
        return jsonify("There are no trusted ip")
    return jsonify(list(trusted_ips))
def get_client_ip():
    if request.headers.getlist("X-Forwarded-For"):
        ip = request.headers.getlist("X-Forwarded-For")[0]
    else:
        ip = request.remote_addr
    return ip



def get_client_ip():
    if request.headers.getlist("X-Forwarded-For"):
        ip = request.headers.getlist("X-Forwarded-For")[0]
    else:
        ip = request.remote_addr
    return ip

# def check_user(email):
#     if email is None  :
#             return jsonify({"error": "null is not accepted"}), 400
#     try:
#         query ="SELECT * FROM users where username = ?"
#         values=(email)
#         result=execute_query(query,values)
#         return result!=None 
#     except Exception as e:
#         print(e)

@app.route("/")
def index():
    create_table()
    return render_template("index.html")
@app.route("/docs")
def docs():
    return render_template("docs.html")
# @app.route("/add_key")
# @require_api_key
# def addKey():
#     return render_template('add_keys.html')
# @app.route("/registration")
# def register_page():
#     return render_template("register.html")
# def register_user(email, password):

#     try:
#         # Define the INSERT query with placeholders
#         query = "INSERT INTO keys_management (username, password) VALUES (?, ?"

#         # Define the values to insert
#         values = (email, password)

#         # Execute the insert query with parameters
#         return execute_query(query, values)

#     except Exception as ex:
#         print("Exception:", ex)
#         return jsonify({"error": "Internal server error"})
# @app.route("/register", methods=["POST"])
# def register():
#     email = request.form.get("email")
#     password = request.form.get("password")

#     if email and password:
#         register_user(email, password)
#         # Check if the email is already registered
#         if  check_user(email)==False:
#                         return f"this {email} has already exist!"

         
#         else:
#             # Store the email and password (you may want to hash the password for security)
#             register_user(email,password)
#             return f"Registration successful for {email}!"
#         return "you are now a user"
#     else:
#         return "Email and password are required!"

@app.route("/api/insert_key")
@require_api_key
def insert_data():
    k1 = request.args.get("k1") 
    k2 = request.args.get("k2")
    v = request.args.get("v")
    if v is None or k1 is None or k2 is None  :
            return jsonify({"error": "null is not accepted"}), 400

    try:
        # Define the INSERT query with placeholders
        query = "INSERT INTO keys_management (key1, key2, value) VALUES (?, ?, ?)"

        # Define the values to insert
        values = (k1, k2, v)

        # Execute the insert query with parameters
        return execute_query(query, values)

    except Exception as ex:
        print("Exception:", ex)
        return jsonify({"error": "Internal server error"})

@app.route("/api/get_key_db")
@require_api_key
def get_Key_db():

    k1 = request.args.get("k1")
    k2 = request.args.get("k2")
    
    if k1 == "all":
        query = "SELECT key1 , key2  FROM keys_management"
        params = ()
    else:
        if k1 is None or k2 is None  :
            return jsonify({"error": "null is not accepted"}), 400

        query = "SELECT value FROM keys_management WHERE key1=? AND key2=?"
        params = (k1, k2)

    try:
        return execute_query(query, params)
    except sqlite3.Error as e:
        print("SQLite error:", e)
        return jsonify({"error": f"Database error: {e}"}), 500
    except Exception as ex:
        print("Exception:", ex)
        return jsonify({"error": f"Internal server error: {ex}"}), 500



def insert_trusted_ip(ip):
    conn = sqlite3.connect("db\vault.db")  # Ensure the path is correct and use '/' for cross-platform compatibility
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO trusted_ip (ip) VALUES (?);
        ''', (ip,))
        conn.commit()
        return {"message": "The IP was inserted successfully."}
    except Exception as e:
        return {"error": str(e)}
    finally:
        cursor.close()
        conn.close()
def remove_ip_db(ip):
    conn = sqlite3.connect("db\vault.db")  # Ensure the path is correct and use '/' for cross-platform compatibility
    cursor = conn.cursor()
    try:
        cursor.execute('''
            DELETE FROM trusted_ip WHERE ip = ?;
        ''', (ip,))

        conn.commit()
        return {"message": "The IP was deleted successfully."}
    except Exception as e:
        return {"error": str(e)}
    finally:
        cursor.close()
        conn.close()
@require_api_key
@app.route('/api/add_trusted_ip', methods=['GET'])
def add_ip():
    ip = request.args.get("ip")
    if not ip:
        return jsonify({"error": "No IP provided"}), 400
    else:
        result = insert_trusted_ip(ip)
        if "error" in result:
            return jsonify(result), 500
        else:
            return jsonify(result), 200
       
@require_api_key
@app.route('/api/remove_ip', methods=['GET'])
def remove_ip():
    ip=request.args.get("ip")
    if not ip:
        return jsonify({"error": "No IP provided"}), 400
    else:
        try:
            remove_ip_db(ip)
            return jsonify("success"),200
        except Exception as e:
             return jsonify(e),501

@require_api_key
@app.route("/api/getAllIps")
def getIps():
    results=get_trusted_ips()
    return jsonify({"results":results})

def get_firewall_status():
    conn = sqlite3.connect('db\vault.db')
    cursor = conn.cursor()
    cursor.execute('SELECT status FROM firewall_status WHERE id = 1')
    status = cursor.fetchone()
    conn.close()
    return status[0]
@require_api_key
@app.route('/api/get_status', methods=['GET'])
def get_status():
    status = get_firewall_status()
    if status is not None:
        if status ==1 :
            status= True 
        elif status == 0:
            status = False

        return jsonify(status), 200
    else:
        return jsonify({"error": "Status not found"}), 404


@require_api_key
@app.route('/api/update_status', methods=['GET'])
def update_status():
    new_status = request.args.get('status')
    print(new_status)
    
    # Check if new_status is provided and convert it to an integer
    if new_status is None:
        return jsonify({"error": "Status parameter is missing"}), 400
    
    try:
        new_status = int(new_status)
    except ValueError:
        return jsonify({"error": "Invalid status value (not an integer)"}), 400
    
    # Check if new_status is valid (either 0 or 1)
    if new_status != 1 and new_status != 0:
        return jsonify({"error": "Invalid status value (must be 0 or 1)"}), 400

    # Update the database with the new status
    conn = sqlite3.connect('db\vault.db')  # Use forward slash '/' instead of backslash '\' in paths
    cursor = conn.cursor()
    cursor.execute('UPDATE firewall_status SET status = ? WHERE id = 1', (new_status,))
    conn.commit()
    conn.close()
    
    return jsonify({"message": "Status updated"}), 200

def gettoken():
        conn = sqlite3.connect("db\vault.db")
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM tokens ")
        result = cursor.fetchone()
        conn.close()
	
        print(result)
# gettoken()        
