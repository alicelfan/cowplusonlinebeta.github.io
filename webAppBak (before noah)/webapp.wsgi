#!/var/www/webApp/venv/bin/python3.11
import sys
import logging
import site

logging.basicConfig(stream=sys.stderr)
sys.path.insert(0,"/var/www/webApp/")

# Import the Flask application
from webApp import app as application

# Set the application's secret key
application.secret_key = 'your_secret_key'