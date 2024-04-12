from flask import Flask, render_template, request, jsonify
import requests
import mysql.connector

app = Flask(__name__)

# Database connection details 
db_config = {
    "host": "localhost",
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
  try:
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    # Check if table exists using reflection
    engine = connection.engine
    inspector = connection.inspect(engine)
    exists = inspector.has_table('cve_data')

    if not exists:
      # Create table if it doesn't exist
      create_table_query = """
        CREATE TABLE cve_data (
          id VARCHAR(255) PRIMARY KEY,
          cvss VARCHAR(20),
          software_version VARCHAR(100),
          cve_type VARCHAR(50),
          date VARCHAR(20)
        );
      """
      cursor.execute(create_table_query)
      connection.commit()
      print("Created CVE data table")

    # Build SQL insert query with placeholders for values
    query = """
        INSERT INTO cve_data (id, cvss, software_version, cve_type, date)
        VALUES (%s, %s, %s, %s, %s)
    """
    for cve in cve_data["results"]["CVE_data_items"]:
      cve_details = cve["cve"]["CVE_data_meta"]
      cursor.execute(query, (
        cve_details["ID"],
        cve_details.get("cvss", None),  # Handle potential missing CVSS data
        cve["configurations"][0]["cpe"]["product"]["version"],  # Assuming first entry for software version
        cve_details["cve_type"],
        cve_details["published"],
      ))
    connection.commit()
    connection.close()
    return "CVE data stored successfully!"
  except requests.exceptions.RequestException as e:
    return f"Error fetching data from NVD: {str(e)}"
  except mysql.connector.Error as e:
    return f"Error storing data in database: {str(e)}"

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
