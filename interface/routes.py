#Importación de funciones
from flask_login.utils import logout_user
from interface import app, db
from flask import render_template, redirect, url_for, flash
from interface.models import Users
from interface.forms import *
from flask_login import login_user, logout_user, login_required
from interface.automation import *
from netmiko import ssh_exception

#Creacion del directorio home
@app.route('/')
def homePage():
    #Renderización del HTML
    return render_template('home.html')

#Creación del directorio de login con métodos GET y POST para permitir envío de datos
@app.route('/login', methods=['GET', 'POST'])
def loginPage():
    loginForm = LoginForm()
    #Validación de datos ingresados
    if loginForm.validate_on_submit():
        #Consulta a la base de datos por el usuario
        attempted_user = Users.query.filter_by(username=loginForm.username.data).first()
        #Realizar login en caso de que las credenciales sean válidas
        if attempted_user and attempted_user.check_password(attempted_password=loginForm.password1.data):
            login_user(attempted_user)
            #Mensaje de éxito y redirección al nuevo directorio
            flash('Succesful log in', category='success')
            return redirect(url_for('showRunPage'))
        else:
            #Mensaje de error
            flash('Incorrect username or password', category='danger')
    #Renderización del HTML y envio del form
    return render_template('login.html', form=loginForm)

@app.route('/register', methods = ['GET', 'POST'])
def registerPage():
    registerForm = RegisterForm()
    if registerForm.validate_on_submit():
        #Inserción de datos para crear el usuario en la base de datos
        userToCreate = Users(username = registerForm.username.data,
                            unhashed_password = registerForm.password1.data)
        db.session.add(userToCreate)
        db.session.commit()
        login_user(userToCreate)
        flash('Account created succesfully', category='success')
        return redirect(url_for('showRunPage'))
    if registerForm.errors != {}:
        for errorMsg in registerForm.errors.values():
            flash(f'There was an error with creating a user {errorMsg}', category='danger')
    return render_template('register.html', form=registerForm)

@app.route('/logout')
def logoutPage():
    logout_user()
    flash('You have been logged out', category='info')
    return redirect(url_for('homePage'))

@app.route('/show_config', methods = ['GET', 'POST'])
@login_required
def showRunPage():
    output = ''
    show_run_form = ShowRunForm()
    if show_run_form.validate_on_submit():
        try:
            #Envio de datos para realizar la conexión mediante netmiko
            output = showRunningConfig(ip_address=show_run_form.ip_address.data,
                                    username=show_run_form.username.data,
                                    password=show_run_form.password.data,
                                    configuration=show_run_form.configuration.data)
            flash('Succesful configuration!', category='success')
        except ssh_exception.NetmikoTimeoutException:
            #Mensaje de error en caso de no lograr conexión
            flash('Can not connect to the specified device', category='danger')
        except ssh_exception.NetMikoAuthenticationException:
            #Mensaje de error en caso de proveer credenciales erróneas
            flash('Incorrect username/s or password/s', category='danger')
    if show_run_form.errors != {}:
        for errorMsg in show_run_form.errors.values():
            flash(f'There is an error within the configuration data: {errorMsg}', category='danger')
    #Se envía la salida del dispositivo de red en config_output para que se renderize como HTML
    return render_template('showRun.html', form=show_run_form, config_output=output)

#Las demás funciones a partir de aquí siguen el mismo patrón, solo cambia el form y la función
#de automatización
@app.route('/vlan', methods = ['GET', 'POST'])
@login_required
def vlanPage():
    output = ''
    vlan_form = VlanForm()
    if vlan_form.validate_on_submit():
        try:
            output = createVlans(ip_address=vlan_form.ip_address.data,
                                username=vlan_form.username.data,
                                password=vlan_form.password.data,
                                vlan_numbers=vlan_form.vlan_numbers.data,
                                vlan_names=vlan_form.vlan_names.data)
            flash('Succesful configuration!', category='success')
        except ssh_exception.NetmikoTimeoutException:
            flash('Can not connect to the specified device', category='danger')
        except ssh_exception.NetMikoAuthenticationException:
            flash('Incorrect username/s or password/s', category='danger')
    if vlan_form.errors != {}:
        for errorMsg in vlan_form.errors.values():
            flash(f'There is an error within the configuration data: {errorMsg}', category='danger')
    return render_template('vlan.html', form=vlan_form, config_output=output)

@app.route('/ip_address', methods = ['GET', 'POST'])
@login_required
def ipAddressPage():
    output = ''
    ip_address_form = IPAddressForm()
    if ip_address_form.validate_on_submit():
        try:
            output = configIpAddress(ip_address=ip_address_form.ip_address.data,
                                    username=ip_address_form.username.data,
                                    password=ip_address_form.password.data,
                                    interface=ip_address_form.interface.data,
                                    int_ip_address=ip_address_form.config_ip_address.data,
                                    network_mask=ip_address_form.network_mask.data,
                                    desc=ip_address_form.description.data)
            flash('Succesful configuration!', category='success')
        except ssh_exception.NetmikoTimeoutException:
            flash('Can not connect to the specified device', category='danger')
    if ip_address_form.errors != {}:
        for errorMsg in ip_address_form.errors.values():
            flash(f'There is an error within the configuration data: {errorMsg}', category='danger')
    return render_template('ipAddress.html', form=ip_address_form, config_output=output)

@app.route('/port_security', methods = ['GET', 'POST'])
@login_required
def portSecurityPage():
    output = ''
    port_security_form = PortSecurityForm()
    if port_security_form.validate_on_submit():
        try:
            output = portSecurity(ip_address=port_security_form.ip_address.data,
                                username=port_security_form.username.data,
                                password=port_security_form.password.data,
                                interface=port_security_form.interface.data,
                                max_mac_address=port_security_form.max_mac_address.data,
                                violation_measure=port_security_form.violation_measure.data)
            flash('Succesful configuration!', category='success')
        except ssh_exception.NetmikoTimeoutException:
            flash('Can not connect to the specified device', category='danger')
    if port_security_form.errors != {}:
        for errorMsg in port_security_form.errors.values():
            flash(f'There is an error within the configuration data: {errorMsg}', category='danger')
    return render_template('portSecurity.html', form=port_security_form, config_output=output)

@app.route('/create_user', methods=('GET', 'POST'))
@login_required
def createUserPage():
    output = ''
    create_user_form = CreateUserForm()
    if create_user_form.validate_on_submit():
        try:
            output = createUser(ip_address=create_user_form.ip_address.data, 
                                username=create_user_form.username.data, 
                                password=create_user_form.password.data, 
                                new_user=create_user_form.new_user.data, 
                                new_password=create_user_form.new_password.data, 
                                privilege_level=create_user_form.privilege_level.data)
            flash('Succesful configuration!', category='success')
        except ssh_exception.NetmikoTimeoutException:
            flash('Can not connect to the specified device', category='danger')
    if create_user_form.errors != {}:
        for errorMsg in create_user_form.errors.values():
            flash(f'There is an error withing the configuration data: {errorMsg}', category='danger')
    return render_template('user.html', form=create_user_form, config_output=output)

@app.route('/dhcp_config', methods=('GET', 'POST'))
@login_required
def dhcpConfigPage():
    output = ''
    dhcp_config_form = DHCPConfigForm()
    if dhcp_config_form.validate_on_submit():
        try:
            output = dhcpConfig(ip_address=dhcp_config_form.ip_address.data, 
                                username=dhcp_config_form.username.data, 
                                password=dhcp_config_form.password.data, 
                                dhcp_pool=dhcp_config_form.dhcp_pool.data, 
                                network_ip=dhcp_config_form.network_ip.data, 
                                network_mask=dhcp_config_form.network_mask.data, 
                                default_router=dhcp_config_form.default_router.data, 
                                domain_name=dhcp_config_form.domain_name.data, 
                                dns_server=dhcp_config_form.dns_server.data)
            flash('Succesful configuration!', category='success')
        except ssh_exception.NetmikoTimeoutException:
            flash('Can not connect to the specified device', category='danger')
    if dhcp_config_form.errors != {}:
        for errorMsg in create_user_form.errors.values():
            flash(f'There is an error withing the configuration data: {errorMsg}', category='danger')
    return render_template('dhcp.html', form=dhcp_config_form, config_output=output)

@app.route('/ospf_config', methods=('GET', 'POST'))
@login_required
def ospfConfigPage():
    output = ''
    ospf_config_form = OSPFConfigForm()
    if ospf_config_form.validate_on_submit():
        try:
            output = ospfConfig(ip_address=ospf_config_form.ip_address.data, 
                                username=ospf_config_form.username.data, 
                                password=ospf_config_form.password.data, 
                                process_id=ospf_config_form.process_id.data, 
                                network_ip=ospf_config_form.network_ip.data, 
                                wildcard_mask=ospf_config_form.wildcard_mask.data, 
                                area_id=ospf_config_form.area_id.data)
            flash('Succesful configuration!', category='success')
        except ssh_exception.NetmikoTimeoutException:
            flash('Can not connect to the specified device', category='danger')
    if ospf_config_form.errors != {}:
        for errorMsg in create_user_form.errors.values():
            flash(f'There is an error withing the configuration data: {errorMsg}', category='danger')
    return render_template('ospf.html', form=ospf_config_form, config_output=output)

@app.route('/static_route_config', methods=('GET', 'POST'))
@login_required
def staticRouteConfigPage():
    output = ''
    static_route_config_form = StaticRouteForm()
    if static_route_config_form.validate_on_submit():
        try:
            output = staticRouteConfig(ip_address=static_route_config_form.ip_address.data, 
                                username=static_route_config_form.username.data, 
                                password=static_route_config_form.password.data,  
                                network_ip=static_route_config_form.network_ip.data, 
                                network_mask=static_route_config_form.network_mask.data, 
                                next_hop_ip=static_route_config_form.next_hop_ip.data)
            flash('Succesful configuration!', category='success')
        except ssh_exception.NetmikoTimeoutException:
            flash('Can not connect to the specified device', category='danger')
    if static_route_config_form.errors != {}:
        for errorMsg in create_user_form.errors.values():
            flash(f'There is an error withing the configuration data: {errorMsg}', category='danger')
    return render_template('staticRoute.html', form=static_route_config_form, config_output=output)

@app.route('/rip_config', methods=('GET', 'POST'))
@login_required
def RIPConfigPage():
    output = ''
    rip_config_form = RIPConfigForm()
    if rip_config_form.validate_on_submit():
        try:
            output = staticRouteConfig(ip_address=rip_config_form.ip_address.data, 
                                username=rip_config_form.username.data, 
                                password=rip_config_form.password.data,  
                                network_ip=rip_config_form.network_ip.data)
            flash('Succesful configuration!', category='success')
        except ssh_exception.NetmikoTimeoutException:
            flash('Can not connect to the specified device', category='danger')
    if rip_config_form.errors != {}:
        for errorMsg in create_user_form.errors.values():
            flash(f'There is an error withing the configuration data: {errorMsg}', category='danger')
    return render_template('rip.html', form=rip_config_form, config_output=output)