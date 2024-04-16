from flask import Flask, render_template, request, jsonify
import requests
import mysql.connector
from time import sleep  # for retry pauses

app = Flask(__name__)

# Database connection details
db_config = {
    "host": "mysql",
    "user": "root",
    "password": "password",
    "database": "cve_data"
}

# NVD API endpoint for Microsoft Word CVEs
nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=microsoft+word"

def fetch_cve_data():
    response = requests.get(nvd_api_url)
    response.raise_for_status()  # Raise an exception for non-200 status codes
    return response.json()

def store_cve_data(cve_data):
    # Create table if it doesn't exist
    create_table_query = """
         CREATE TABLE cve_table (
           id VARCHAR(255) PRIMARY KEY,
           cvssV2 VARCHAR(1000),
           cvssV3 VARCHAR(1000),
           description TEXT(100000),
           last_modified VARCHAR(1000),
           first_criteria VARCHAR(1000)
    );
    """

    try:
        MAX_RETRIES = 20  # Define the maximum number of attempts
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                connection = mysql.connector.connect(**db_config)
                print(f"Connected successfully on attempt {attempt}!\n")
                break  # Exit the loop on successful connection
            except mysql.connector.Error as err:
                print(f"Connection failed on attempt {attempt}: {err}")
                if attempt == MAX_RETRIES:
                    print("Reached maximum retries. Exiting...")
                    exit(1)  # Exit the program with an error code
                else:
                    delay = 2 ** attempt  # Exponential backoff for retries
                    print(f"Retrying in {delay} seconds...")
                    sleep(delay)
        cursor = connection.cursor()
        cursor.execute(create_table_query)
        connection.commit()
        print("Created CVE data table\n")
    except mysql.connector.Error as err:
        if "already exists" in str(err):
            print("Table already Exists")
        else:
            print("Error:", err)
    finally:
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
        print(f"An error occured: {str(e)}")
      finally:
          print("Sucessful insertion of data")
    connection.close()

"""
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        try:
            cve_data = fetch_cve_data()
            message = store_cve_data(cve_data)
            return render_template("index.html", message=message)
        except Exception as e:  # Catch any unexpected exceptions
            return f"An error occurred: {str(e)}"

    return render_template("index.html")
"""
@app.route("/", methods=["GET", "POST"])
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
    search_term = request.form.get("search_term")
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    # Build dynamic query based on search term
    query = f"SELECT * FROM cve_data WHERE id LIKE %s OR software_version LIKE %s OR cve_type LIKE %s"
    cursor.execute(query, ("%" + search_term + "%", "%" + search_term + "%", "%" + search_term + "%"))
    cve_data = cursor.fetchall()

    connection.close()
    return jsonify(cve_data)  # Return search results as JSON


@app.route("/sort/<sort_attribute>", methods=["GET"])
def sort(sort_attribute):
    valid_attributes = ["id", "cvss", "software_version", "cve_type", "date"]
    if sort_attribute not in valid_attributes:
        return jsonify({"error": "Invalid sort attribute"})

    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    query = f"SELECT * FROM cve_data ORDER BY {sort_attribute}"
    cursor.execute(query)
    cve_data = cursor.fetchall()

    connection.close()
    return jsonify(cve_data)  # Return sorted data as JSON


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
