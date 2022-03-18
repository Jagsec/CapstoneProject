#Importación de modulos
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
#Esta importación está comentada porque solo se utilizó para comprobar el funcionamiento
#remoto de la aplicación
#from flask_ngrok import run_with_ngrok

#Inicialización de la app
app = Flask(__name__)
#Configuración de la base de datos
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SECRET_KEY'] = 'f8cab83eebd77c5aac37048d'
db = SQLAlchemy(app)
#Encriptación de las contraseñas
bcrypt = Bcrypt(app)
#Manejo de login de usuarios
login_manager = LoginManager(app)
login_manager.login_view = 'loginPage'
login_manager.login_message_category = 'info'
#Al igual que la importación de antes, esto solo fue usado para probar el funcionamiento remoto
#run_with_ngrok(app)
from interface import routes