#Importación de funciones
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DecimalField, SelectField
from wtforms.validators import Length, EqualTo, DataRequired, NumberRange, ValidationError, IPAddress
from interface.models import Users
from interface.formating import single_address, single_address_validation, multiple_address_validation

#Función de validación para determinar si la o las direcciones ip son válidas
#Se utilizan funciones del archivo formating.py
def validate_ip_address(self, ip_addresses):
    is_single = single_address(ip_addresses.data)
    if is_single:
        if not single_address_validation(ip_addresses.data):
            raise ValidationError('Invalid ip address')
    else:
        if not multiple_address_validation(ip_addresses.data):
            raise ValidationError('One or more ip addresses are not valid')

#Form con los datos de login y validaciones respectivas
class LoginForm(FlaskForm):
    username = StringField(label='Username', validators=[DataRequired()])
    password1 = PasswordField(label='Password', validators=[DataRequired()])
    submit = SubmitField(label='Submit')

#Form para el registro de usuarios 
class RegisterForm(FlaskForm):
    #Función para validar si el usuario existe o no antes de registrarlo
    def validate_username(self, username_to_check):
        user = Users.query.filter_by(username=username_to_check.data).first()
        if user:
            raise ValidationError('Username already exists, please try another one')

    username = StringField(label='Username', validators=[Length(min=2, max=30), DataRequired()])
    password1 = PasswordField(label='Password', validators=[Length(min=8), DataRequired()])
    password2 = PasswordField(label='Confirmation', validators=[EqualTo('password1'), DataRequired()])
    submit = SubmitField(label='Submit')

#Form base del cuál los demás heredan los campos en común
class BaseForm(FlaskForm):
    ip_address = StringField(label='Device IP Address', validators=[DataRequired(), validate_ip_address])
    username = StringField(label='Username', validators=[DataRequired()])
    password = PasswordField(label='Password', validators=[DataRequired()])
    submit = SubmitField(label='Submit')

#Form para los diferentes tipos de show de manera que se muestren como menú
class ShowRunForm(BaseForm):
    configuration = SelectField(label='Configuration', choices=[('running-config','Running Configuration'),
                                                                ('version','Version'),('ip int brief', 'IP Interfaces'),
                                                                ('protocols','Protocols'),('ip route','Routing Table'),
                                                                ('access-lists','Access Lists'), ('vlan', 'VLANs'),
                                                                ('save-config', 'Save Configurations')])

#Form para creación de VLANs
class VlanForm(BaseForm):
    vlan_numbers = StringField(label='VLAN numbers', validators=[DataRequired()])
    vlan_names = StringField(label='VLAN names', validators=[DataRequired(())])

#Form para asignación de direcciones ip
class IPAddressForm(BaseForm):
    interface = StringField(label='Interface', validators=[DataRequired()])
    config_ip_address = StringField(label='Interface IP Address', validators=[validate_ip_address, DataRequired()])
    network_mask = StringField(label="Network Mask", validators=[validate_ip_address, DataRequired()])
    description = StringField(label='Description', validators=[Length(min=2, max=20), DataRequired()])

#Form para configuración de seguridad de puertos en capa 2
class PortSecurityForm(BaseForm):
    interface = StringField(label='Interface', validators=[DataRequired()])
    max_mac_address = DecimalField(label='Max. MAC Address #', validators=[DataRequired(), NumberRange(min=1, max=9)])
    violation_measure = SelectField(label='Violation Measure', choices=[('protect', 'Protect'),
                                                                        ('restrict', 'Restrict'),
                                                                        ('shutdown', 'Shutdown')])

#Form para creación de usuarios
class CreateUserForm(BaseForm):
    new_user = StringField(label='New User', validators=[DataRequired()])
    new_password = StringField(label='New Password', validators=[DataRequired(), Length(min=8)])
    privilege_level = DecimalField(label='Privilege', validators=[DataRequired(), NumberRange(min=0, max=15)])

#Form para configuración de DHCP
class DHCPConfigForm(BaseForm):
    dhcp_pool = StringField(label='DHCP Pool', validators=[DataRequired()])
    network_ip = StringField(label='Network IP', validators=[validate_ip_address, DataRequired()])
    network_mask = StringField(label='Network Mask', validators=[validate_ip_address, DataRequired()])
    default_router = StringField(label='Default Router', validators=[validate_ip_address, DataRequired()])
    domain_name = StringField(label='Domain Name', validators=[DataRequired()])
    dns_server = StringField(label='DNS Server', validators=[validate_ip_address, DataRequired()])

#Form para configuración de OSPF
class OSPFConfigForm(BaseForm):
    process_id = StringField(label='Process ID', validators=[DataRequired()])
    network_ip = StringField(label='Network IP', validators=[validate_ip_address, DataRequired()])
    wildcard_mask = StringField(label='Wildcard Mask', validators=[validate_ip_address, DataRequired()])
    area_id = StringField(label='Area ID', validators=[DataRequired()])

#Form para configuración de una ruta estática
class StaticRouteForm(BaseForm):
    network_ip = StringField(label='Network IP', validators=[validate_ip_address, DataRequired()])
    network_mask = StringField(label='Network Mask', validators=[validate_ip_address, DataRequired()])
    next_hop_ip = StringField(label='Next Hop', validators=[validate_ip_address, DataRequired()])

#Form para configuración de RIP
class RIPConfigForm(BaseForm):
    network_ip = StringField(label='Network IP', validators=[validate_ip_address, DataRequired()])