import os
from dotenv import load_dotenv

app_dir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(app_dir,'.env'))

import urllib
db_password_quoted = urllib.parse.quote(os.environ.get('DB_PASS'))

class BaseConfig:
    # General Config
    SECRET_KEY = os.environ.get('SECRET_KEY')
    FLASK_APP = os.environ.get('FLASK_APP')
    FLASK_ENV = os.environ.get('FLASK_ENV')

    # Database
    SQLALCHEMY_DATABASE_URI=f"{os.environ.get('DB_ENGINE')}{os.environ.get('DB_USERNAME')}:{db_password_quoted}@{os.environ.get('DB_HOST')}/{os.environ.get('DB_NAME')}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_POOL_RECYCLE = 299
