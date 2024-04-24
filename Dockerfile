FROM python:3.9

WORKDIR /app

RUN pip install Flask requests mysql-connector-python bleach flask_sslify

COPY . .

CMD ["python", "WebUI.py"]
