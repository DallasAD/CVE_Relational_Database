# CVE_Relational_Database

## Step 1: Clone this repository 
```bash
git clone https://github.com/DallasAD/CVE_Relational_Database
```
## Step 2: Install Docker
```bash
apt install docker
```
## Step 3: Run Docker containers using docker-compose. Make sure you are in the project directory.
```bash
docker-compose up -d
```
## Step 4: Check that both the WebUI and MySQL containers are running
```bash
docker-compose ps
```
## Step 5: View the Web Page
Type `https://127.0.0.1:5000` into the address bar of your web browser.
## Step 6: Stop the Docker containers
```bash
docker-compose down
```
## How to generate a new self-signed certificate and private key
```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout localhost.key -out localhost.crt -subj "/CN=localhost"
```
