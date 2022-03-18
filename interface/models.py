#Importación de funciones
from interface import db, bcrypt, login_manager
from flask_login import UserMixin

#Función para retornar una consulta de usuarios
@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

#Tabla de usuarios
class Users(db.Model, UserMixin):
    id = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(length=30), nullable=False, unique=True)
    password = db.Column(db.String(length=30), nullable=False)

    #Función para retornar la contraseña desencriptada
    @property
    def unhashed_password(self):
        return self.unhashed_password

    @unhashed_password.setter
    def unhashed_password(self, plain_text_password):
        self.password = bcrypt.generate_password_hash(plain_text_password).decode('utf-8')

    #Validación de contraseñas
    def check_password(self, attempted_password):
        return bcrypt.check_password_hash(self.password, attempted_password)