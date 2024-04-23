from flask import Flask, render_template, request, jsonify, redirect, url_for, session # flask web backend library
import requests # handle web requests
import mysql.connector # connect to mysql database
from time import sleep  # for retry pauses
import bleach  # Import bleach for input sanitization
from flask_sslify import SSLify # for Implementing HTTPs
import hashlib # for hashing the passwords

app = Flask(__name__)
sslify = SSLify(app)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

nvd_api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch="

# Database connection details
db_config = {
    "host": "mysql",
    "user": "root",
    "password": "password",
    "database": "cve_data"
}

# Function to sanitize input using bleach
def sanitize_input(input_string):
    return bleach.clean(input_string, strip=True)

def fetch_cve_data():
    response = requests.get(nvd_api_url)
    response.raise_for_status()  # Raise an exception for non-200 status codes
    return response.json()

def create_tables(cursor):
    create_cve_table_query = """
         CREATE TABLE IF NOT EXISTS cve_table (
           id VARCHAR(255) PRIMARY KEY,
           cvssV2 VARCHAR(1000),
           cvssV3 VARCHAR(1000),
           description TEXT,
           last_modified VARCHAR(1000),
           first_criteria VARCHAR(1000)
    );
    """
    cursor.execute(create_cve_table_query)

    # Create Web_Users table
    create_users_table_query = """
         CREATE TABLE IF NOT EXISTS Web_Users (
           username VARCHAR(255) PRIMARY KEY,
           password VARCHAR(255),
           isAdmin TINYINT(1)
    );
    """
    cursor.execute(create_users_table_query)

    # Insert default user
    insert_default_user_query = """
        INSERT INTO Web_Users (username, password, isAdmin) VALUES (%s, %s, %s)
        ON DUPLICATE KEY UPDATE username=username;
    """

    # Hash the default password before insertion
    defaultAdmin_password_hash = hashlib.sha256("admin".encode()).hexdigest()
    defaultUser_password_hash = hashlib.sha256("password".encode()).hexdigest()

    cursor.execute(insert_default_user_query, ("admin", defaultAdmin_password_hash, 1))
    cursor.execute(insert_default_user_query, ("user", defaultUser_password_hash, 0))


def store_cve_data(connection, cursor, cve_data):
    try:
        # Build SQL insert query with placeholders for values
        query = """
            INSERT IGNORE INTO cve_table (id, cvssV2, cvssV3, description, last_modified, first_criteria)
            VALUES (%s, %s, %s, %s, %s, %s)
        """

        for i in range(0, len(cve_data['vulnerabilities'])):
            vulnerability = cve_data['vulnerabilities'][i]['cve']

            id = "0"
            try:
                id = vulnerability['id']
            except:
                pass
            finally:
                if id == "0":
                    id = "N/A"

            cvssV2 = "0"
            try:
                cvssV2 = vulnerability['metrics']['cvssMetricV2'][0]['cvssData']['baseScore']
            except:
                pass
            finally:
                if cvssV2 == "0":
                    cvssV2 = "N/A"

            cvssV3 = "0"
            try:
                cvssV3 = vulnerability['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
            except:
                pass
            finally:
                if cvssV3 == "0":
                    cvssV3 = "N/A"

            description = "0"
            try:
                description = vulnerability['descriptions'][0]['value']
            except:
                pass
            finally:
                if description == "0":
                    description = "N/A"

            last_modified = "0"
            try:
                last_modified = vulnerability['lastModified']
            except:
                pass
            finally:
                if last_modified == "0":
                    last_modified = "N/A"

            first_criteria = "0"
            try:
                first_criteria = vulnerability['configurations'][0]['nodes'][0]['cpeMatch'][0]['criteria']
            except:
                pass
            finally:
                if first_criteria == "0":
                    first_criteria = "N/A"

            cursor.execute(query, (
                id,
                cvssV2,
                cvssV3,
                description,
                last_modified,
                first_criteria,
            ))
            connection.commit()

    except Exception as e:
        print(f"An error occurred: {str(e)}")
    finally:
        print("Successful insertion of data")

@app.route("/", methods=["GET", "POST"])
def login():
    # create tables
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    create_tables(cursor)  # create the tables
    connection.commit()

    if request.method == "POST":

        username = sanitize_input(request.form.get("username"))
        password = sanitize_input(request.form.get("password"))

        query = "SELECT * FROM Web_Users WHERE username = %s AND password = %s"
        cursor.execute(query, (username, password))
        user_row = cursor.fetchone()

        cursor.close()
        connection.close()

        if user_row:
            user = dict(zip(cursor.column_names, user_row))  # Convert tuple to dictionary
            session['isAdmin'] = user['isAdmin']
            if session['isAdmin'] == 1:
                session['panel'] = 'adminpanel'  # Set panel cookie for admin
                return redirect(url_for('adminpanel'))  # admin panel
            else:
                session['panel'] = 'userpanel'  # Set panel cookie for user
                return redirect(url_for('userpanel'))  # Redirect to user panel
        else:
            return render_template("login.html", error="Invalid username or password")

    return render_template("login.html")

@app.route("/adminpanel", methods=["GET", "POST"])
def adminpanel():
    if 'isAdmin' in session and session['isAdmin'] == 1:
        if request.method == "POST":
            try:
                cve_data = fetch_cve_data()
                if cve_data:
                    connection = mysql.connector.connect(**db_config)
                    cursor = connection.cursor()
                    store_cve_data(connection, cursor, cve_data)

                    return jsonify({"message": "CVE Database updated successfully"})
                else:
                    return jsonify({"error": "Failed to fetch CVE data"})
            except Exception as e:
                return jsonify({"error": "An error occurred while updating CVE database"})
        return render_template("admin.html")
    else:
        return redirect(url_for('userpanel'))


@app.route("/userpanel", methods=["GET", "POST"])
def userpanel():
    if 'isAdmin' in session and session['isAdmin'] == 0:
        return render_template("user.html")
    else:
        return redirect(url_for('adminpanel'))  # Redirect to admin panel if admin tries to access user panel


@app.route("/apiQuery", methods=["POST"])
def apiQuery():
    try:
        search_term = sanitize_input(request.form.get("search_term"))
        global nvd_api_url
        nvd_api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={search_term}"
        return jsonify({"message": "API Query change successfully"})
    except Exception as e:
        return jsonify({"error": "An error occurred while updating API Query"})

@app.route("/search", methods=["POST"])
def search():
    search_term = sanitize_input(request.form.get("search_term"))
    column = sanitize_input(request.form.get("column"))  # New: Get the column to search in
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    # Build dynamic query based on search term and selected column
    query = f"SELECT * FROM cve_table WHERE {column} LIKE %s"  # New: Dynamically construct query
    cursor.execute(query, ("%" + search_term + "%",))
    cve_data = cursor.fetchall()

    connection.close()
    return jsonify(cve_data)  # Return search results as JSON

"""
@app.route("/sort/<sort_attribute>", methods=["GET"])
def sort(sort_attribute):
    sort_attribute = sanitize_input(sort_attribute)
    valid_attributes = ["id", "cvssV2", "cvssV3", "description", "last_modified", "first_criteria"]
    if sort_attribute not in valid_attributes:
        return jsonify({"error": "Invalid sort attribute"})

    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    query = f"SELECT * FROM cve_table ORDER BY {sort_attribute}"
    cursor.execute(query)
    cve_data = cursor.fetchall()

    connection.close()
    return jsonify(cve_data)  # Return sorted data as JSON
"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, ssl_context=('localhost.crt', 'localhost.key'), debug=True)