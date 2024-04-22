from flask import Flask, render_template, request, jsonify, redirect, url_for
import requests
import mysql.connector
from time import sleep  # for retry pauses
import bleach  # Import bleach for input sanitization
from flask_sslify import SSLify # for SSL
import hashlib

app = Flask(__name__)
sslify = SSLify(app)

# Database connection details
db_config = {
    "host": "mysql",
    "user": "root",
    "password": "password",
    "database": "cve_data"
}

# NVD API endpoint for Microsoft Word CVEs
nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=microsoft+word"

# Function to sanitize input using bleach
def sanitize_input(input_string):
    return bleach.clean(input_string, strip=True)

def fetch_cve_data():
    response = requests.get(nvd_api_url)
    response.raise_for_status()  # Raise an exception for non-200 status codes
    return response.json()

def create_tables(cursor):
    create_table_query = """
         CREATE TABLE IF NOT EXISTS cve_table (
           id VARCHAR(255) PRIMARY KEY,
           cvssV2 VARCHAR(1000),
           cvssV3 VARCHAR(1000),
           description TEXT,
           last_modified VARCHAR(1000),
           first_criteria VARCHAR(1000)
    );
    """
    cursor.execute(create_table_query)

    # Create Web_Users table
    create_users_table_query = """
         CREATE TABLE IF NOT EXISTS Web_Users (
           username VARCHAR(255) PRIMARY KEY,
           password VARCHAR(255)
    );
    """
    cursor.execute(create_users_table_query)

    # Insert default user
    insert_default_user_query = """
        INSERT INTO Web_Users (username, password) VALUES (%s, %s)
        ON DUPLICATE KEY UPDATE username=username;
    """

    # Hash the default password before insertion
    defaultAdmin_password_hash = hashlib.sha256("admin".encode()).hexdigest()
    defaultUser_password_hash = hashlib.sha256("password".encode()).hexdigest()

    cursor.execute(insert_default_user_query, ("admin", defaultAdmin_password_hash))
    cursor.execute(insert_default_user_query, ("user", defaultUser_password_hash))


def store_cve_data(cursor, cve_data):
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
            cursor.connection.commit()

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
        user = cursor.fetchone()

        cursor.close()
        connection.close()

        if user:
            return redirect(url_for('index'))  # Redirect to index page if authentication is successful
        else:
            return render_template("login.html", error="Invalid username or password")

    return render_template("login.html")

@app.route("/index", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        try:
            cve_data = fetch_cve_data()
            if cve_data:
                store_cve_data(cve_data)
                return jsonify({"message": "CVE Database updated successfully"})
            else:
                return jsonify({"error": "Failed to fetch CVE data"})
        except Exception as e:
            return jsonify({"error": "An error occurred while updating CVE database"})

    return render_template("index.html")

@app.route("/search", methods=["POST"])
def search():
    search_term = sanitize_input(request.form.get("search_term"))
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    # Build dynamic query based on search term
    query = f"SELECT * FROM cve_table WHERE id LIKE %s OR cvssV2 LIKE %s OR cvssV3 LIKE %s OR description LIKE %s OR last_modified LIKE %s OR first_criteria LIKE %s"
    cursor.execute(query, ("%" + search_term + "%", "%" + search_term + "%", "%" + search_term + "%", "%" + search_term + "%", "%" + search_term + "%", "%" + search_term + "%"))
    cve_data = cursor.fetchall()

    connection.close()
    return jsonify(cve_data)  # Return search results as JSON


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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, ssl_context=('localhost.crt', 'localhost.key'), debug=True)