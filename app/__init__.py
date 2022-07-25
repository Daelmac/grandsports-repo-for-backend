# importing libraries
from flask import Flask
from flask_cors import CORS
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy

# Create Instances
cors = CORS()
db = SQLAlchemy()
migrate = Migrate()

def configure_database(app):

    @app.before_first_request
    def initialize_database():
        db.create_all()

    @app.teardown_request
    def shutdown_session(exception=None):
        db.session.remove()

def create_app():
    app = Flask(__name__)

    app.config.from_object('config.BaseConfig')
    
    # Pushing Application Context
    with app.app_context():
        db.init_app(app) # Initialise with the new app
        cors.init_app(app) # Initialise CORS with 
        migrate.init_app(app,db) # Initializing Flask Migrate

        configure_database(app) # Configuring Database

        # import routes
        from . import routes

    return app