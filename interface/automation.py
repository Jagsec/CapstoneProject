#Importación de funciones
from netmiko import ConnectHandler
from interface.formating import single_address, string_to_list

#Función para realizar la conexión SSH
def deviceConnection(ip_address, username, password):

    device_info = {
        'device_type': 'cisco_ios',
        'ip': ip_address,
        'username': username,
        'password': password
    }
    return ConnectHandler(**device_info)

#Función para ejecutar los diferentes comandos show
def showRunningConfig(ip_address, username, password, configuration):

    #Configuración en caso de tener una sola dirección ip
    if single_address(ip_address):
        #Conexión al equipo
        net_connect = deviceConnection(ip_address, username, password)
        #Determinar si el usuario quiere guardar configuración
        if configuration.startswith('save'):
            output = net_connect.send_command('wr')
        #De lo contrario enviará un show precedido de la opción que haya elegido
        else:
            output = net_connect.send_command('show ' + str(configuration))
        #Retorno de la salida del equipo
        return output
    #Configuración de varios equipos
    else:
        output = ''
        device_number = 1
        #Pasar los datos a listas para poder iterar sobre ellos
        address_list = string_to_list(ip_address)
        username_list = string_to_list(username)
        password_list = string_to_list(password)
        #Determinar si ingresó más de un nombre de usuario para la conexión
        if len(username_list) > 1:
            #Iteración sobre las distintas listas para conectarse a cada equipo
            for ip_address, username, password in zip(address_list, username_list, password_list):
                output += '\nDevice #' + str(device_number) + ' configuration\n'
                net_connect = deviceConnection(ip_address, username, password)
                #Envío de los comandos
                if configuration.startswith('save'):
                    output += net_connect.send_command('wr')
                else:
                    output += net_connect.send_command('show ' + str(configuration))
                device_number += 1
            #Retorno de la salida del equipo
            return output
        #En caso de que solo haya un nombre de usuario itera solo sobre la lista de direcciones ip
        else:
            for ip_address in address_list:
                output += '\nDevice #' + str(device_number) + ' configuration\n'
                net_connect = deviceConnection(ip_address, username, password)
                #Envío de comandos
                if configuration.startswith('save'):
                    output += net_connect.send_command('wr')
                else:
                    output += net_connect.send_command('show ' + str(configuration))
                device_number += 1
            #Retorno de la salida del equipo
            return output

def createVlans(ip_address, username, password, vlan_numbers, vlan_names):

    #Pasar los strings con los datos de las VLAN a listas
    vlan_number_list = string_to_list(vlan_numbers)
    vlan_name_list = string_to_list(vlan_names)
    #Configuración para un solo equipo
    if single_address(ip_address):
        net_connect = deviceConnection(ip_address, username, password)
        output = ''
        #Iteración por los distintos números y nombres de VLANs
        for number, name in zip(vlan_number_list, vlan_name_list):
            output += f"\nCreating VLAN #{number}\n"
            config_commands = ['vlan ' + str(number), 'name ' +str(name)]
            output += net_connect.send_config_set(config_commands)
        #Retorno de la salida del equipo
        return output
    #Configuración de varios equipos
    else:
        output = ''
        device_number = 1
        #Pasar los strings a listas
        address_list = string_to_list(ip_address)
        username_list = string_to_list(username)
        password_list = string_to_list(password)
        if len(username_list) > 1:
            #Iteración para conectarse a cada equipo
            for ip_address, username, password in zip(address_list, username_list, password_list):
                output += '\nDevice #' + str(device_number) + ' configuration\n'
                net_connect = deviceConnection(ip_address, username, password)
                #Iteración para crear las VLAN
                for number, name in zip(vlan_number_list, vlan_name_list):
                    output += f"\nCreating VLAN #{number}\n"
                    config_commands = ['vlan ' + str(number), 'name ' +str(name)]
                    output += net_connect.send_config_set(config_commands)
                device_number += 1
            #Retorno de la salida del equipo
            return output
        else:
            #Iteración para conectarse a cada equipo
            for ip_address in address_list:
                output += '\nDevice #' + str(device_number) + ' configuration\n'
                net_connect = deviceConnection(ip_address, username, password)
                #Iteración para creación de las VLAN
                for number, name in zip(vlan_number_list, vlan_name_list):
                    output += f"\nCreating VLAN #{number}\n"
                    config_commands = ['vlan ' + str(number), 'name ' +str(name)]
                    output += net_connect.send_config_set(config_commands)
                device_number += 1
            #Retorno de la salida del equipo
            return output

#A partir de aquí las funciones siguen el mismo patrón, los cambios se realizan en
#los datos que son iterables para cada función y los comandos en sí que se usan
#para realizar la configuración
def configIpAddress(ip_address, username, password, interface, int_ip_address, network_mask, desc):
    
    interface_list = string_to_list(interface)
    int_ip_address_list = string_to_list(int_ip_address)
    network_mask_list = string_to_list(network_mask)
    description_list = string_to_list(desc)
    if single_address(ip_address):
        net_connect = deviceConnection(ip_address, username, password)
        output = ''
        for interface, int_address, network_mask, description in zip(interface_list,
                                                                int_ip_address_list,
                                                                network_mask_list,
                                                                description_list):
            output += f'\nConfiguring interface {interface} address {int_address}\n'
            config_commands = ['int ' + str(interface), 'ip add ' + str(int_address) + ' ' + str(network_mask),
                                'des ' + str(description), 'no shutdown']
            output += net_connect.send_config_set(config_commands)
        return output
    else:
        output = ''
        device_number = 1
        address_list = string_to_list(ip_address)
        username_list = string_to_list(username)
        password_list = string_to_list(password)
        if len(username_list) > 1:
            for ip_address, username, password in zip(address_list, username_list, password_list):
                output += '\nDevice #' + str(device_number) + ' configuration\n'
                net_connect = deviceConnection(ip_address, username, password)
                for interface, int_address, network_mask, description in zip(interface_list,
                                                                int_ip_address_list,
                                                                network_mask_list,
                                                                description_list):
                    output += f'\nConfiguring interface {interface} address {int_address}\n'
                    config_commands = ['int ' + str(interface), 'ip add ' + str(int_address) + ' ' + str(network_mask),
                                        'des ' + str(description), 'no shutdown']
                    output += net_connect.send_config_set(config_commands)
                device_number += 1
            return output
        else:
            for ip_address in address_list:
                output += '\nDevice #' + str(device_number) + ' configuration\n'
                net_connect = deviceConnection(ip_address, username, password)
                for interface, int_address, network_mask, description in zip(interface_list,
                                                                int_ip_address_list,
                                                                network_mask_list,
                                                                description_list):
                    output += f'\nConfiguring interface {interface} address {int_address}\n'
                    config_commands = ['int ' + str(interface), 'ip add ' + str(int_address) + ' ' + str(network_mask),
                                        'des ' + str(description), 'no shutdown']
                    output += net_connect.send_config_set(config_commands)
                device_number += 1
            return output

def portSecurity(ip_address, username, password, interface, max_mac_address, violation_measure):
    
    interface_list = string_to_list(interface)
    if single_address(ip_address):
        net_connect = deviceConnection(ip_address, username, password)
        output = ''
        for interface in interface_list:
            output += f'\nConfiguring interface {interface}\n'
            config_commands = ['int ' + str(interface), 'switchport mode access', 'switchport port-security',
                        'switchport port-security maximum ' + str(max_mac_address),
                        'switchport port-security mac-address sticky',
                        'switchport port-security violation ' + str(violation_measure)]
            output += net_connect.send_config_set(config_commands)
        return output
    else:
        output = ''
        device_number = 1
        address_list = string_to_list(ip_address)
        username_list = string_to_list(username)
        password_list = string_to_list(password)
        if len(username_list) > 1:
            for ip_address, username, password in zip(address_list, username_list, password_list):
                output += '\nDevice #' + str(device_number) + ' configuration\n'
                net_connect = deviceConnection(ip_address, username, password)
                for interface in interface_list:
                    output += f'\nConfiguring interface {interface}\n'
                    config_commands = ['int ' + str(interface), 'switchport mode access', 'switchport port-security',
                                'switchport port-security maximum ' + str(max_mac_address),
                                'switchport port-security mac-address sticky',
                                'switchport port-security violation ' + str(violation_measure)]
                    output += net_connect.send_config_set(config_commands)
                device_number += 1
            return output
        else:
            for ip_address in address_list:
                output += '\nDevice #' + str(device_number) + ' configuration\n'
                net_connect = deviceConnection(ip_address, username, password)
                for interface in interface_list:
                    output += f'\nConfiguring interface {interface}\n'
                    config_commands = ['int ' + str(interface), 'switchport mode access', 'switchport port-security',
                                'switchport port-security maximum ' + str(max_mac_address),
                                'switchport port-security mac-address sticky',
                                'switchport port-security violation ' + str(violation_measure)]
                    output += net_connect.send_config_set(config_commands)
                device_number += 1
            return output

def createUser(ip_address, username, password, new_user, new_password, privilege_level):

    new_user_list = string_to_list(new_user)
    new_password_list = string_to_list(new_password)
    if single_address(ip_address):
        net_connect = deviceConnection(ip_address, username, password)
        output = ''
        for new_user, new_password, privilege_level in zip(new_user_list, new_password_list, privilege_level_list):
            output += 'Creating user: ' + str(new_user)
            config_commands = ['username ' + str(new_user) + ' password ' + str(new_password),
                               'username ' + str(new_user) + ' privilege ' + str(privilege_level)]
            output += net_connect.send_config_set(config_commands)
        return output
    else:
        output = ''
        device_number = 1
        address_list = string_to_list(ip_address)
        username_list = string_to_list(username)
        password_list = string_to_list(password)
        if len(username_list) > 1:
            for ip_address, username, password in zip(address_list, username_list, password_list):
                output += '\nDevice #' + str(device_number) + ' configuration\n'
                net_connect = deviceConnection(ip_address, username, password)
                for new_user, new_password in zip(new_user_list, new_password_list):
                    output += 'Creating user: ' + str(new_user) + '\n'
                    config_commands = ['username ' + str(new_user) + ' password ' + str(new_password),
                                    'username ' + str(new_user) + ' privilege ' + str(privilege_level)]
                    output += net_connect.send_config_set(config_commands)
            return output
        else:
            for ip_address in address_list:
                output += '\nDevice #' + str(device_number) + ' configuration\n'
                net_connect = deviceConnection(ip_address, username, password)
                for new_user, new_password in zip(new_user_list, new_password_list):
                    output += 'Creating user: ' + str(new_user) + '\n'
                    config_commands = ['username ' + str(new_user) + ' password ' + str(new_password),
                                    'username ' + str(new_user) + ' privilege ' + str(privilege_level)]
                    output += net_connect.send_config_set(config_commands)
            return output

def dhcpConfig(ip_address, username, password, dhcp_pool, network_ip, network_mask, default_router, 
               domain_name, dns_server):

    dhcp_pool_list = string_to_list(dhcp_pool)
    network_ip_list = string_to_list(network_ip)
    network_mask_list = string_to_list(network_mask)
    if single_address(ip_address):
        net_connect = deviceConnection(ip_address, username, password)
        output = ''
        for dhcp_pool, network_ip, network_mask in zip(dhcp_pool_list, network_ip_list, network_mask_list):
            output += "\nConfiguring " + str(dhcp_pool) + ' pool'
            config_commands = ['ip dhcp pool ' + str(dhcp_pool), 'network ' + str(network_ip) + ' ' + str(network_mask),
                                'default-router ' + str(default_router), 'domain-name ' +str(domain_name),
                                'dns-server ' +str(dns_server)]
            output += net_connect.send_config_set(config_commands)
        return output
    else:
        output = ''
        device_number = 1
        address_list = string_to_list(ip_address)
        username_list = string_to_list(username)
        password_list = string_to_list(password)
        default_router_list = string_to_list(default_router)
        if len(username_list) > 1:
            for ip_address, username, password, default_router in zip(address_list, username_list, 
                                                                      password_list, default_router_list):
                output += '\nDevice #' + str(device_number) + ' configuration\n'
                net_connect = deviceConnection(ip_address, username, password)
                for dhcp_pool, network_ip, network_mask in zip(dhcp_pool_list, network_ip_list, network_mask_list):
                    output += "\nConfiguring " + str(dhcp_pool) + ' pool'
                    config_commands = ['ip dhcp pool ' + str(dhcp_pool), 'network ' + str(network_ip) + ' ' + str(network_mask),
                                        'default-router ' + str(default_router), 'domain-name ' +str(domain_name),
                                        'dns-server ' +str(dns_server)]
                    output += net_connect.send_config_set(config_commands)
            return output
        else:
            for ip_address, default_router in zip(address_list, default_router_list):
                output += '\nDevice #' + str(device_number) + ' configuration\n'
                net_connect = deviceConnection(ip_address, username, password)
                for dhcp_pool, network_ip, network_mask in zip(dhcp_pool_list, network_ip_list, network_mask_list):
                    output += "\nConfiguring " + str(dhcp_pool) + ' pool'
                    config_commands = ['ip dhcp pool ' + str(dhcp_pool), 'network ' + str(network_ip) + ' ' + str(network_mask),
                                        'default-router ' + str(default_router), 'domain-name ' +str(domain_name),
                                        'dns-server ' +str(dns_server)]
                    output += net_connect.send_config_set(config_commands)
            return output

def ospfConfig(ip_address, username, password, process_id, network_ip, wildcard_mask, area_id):

    network_ip_list = string_to_list(network_ip)
    wildcard_mask_list = string_to_list(wildcard_mask)
    if single_address(ip_address):
        net_connect = deviceConnection(ip_address, username, password)
        output = ''
        for network_ip, wildcard_mask in zip(network_ip_list, wildcard_mask_list):
            config_commands = ['router ospf ' + str(process_id), 
                               'network ' + str(network_ip) + ' ' + str(wildcard_mask) + ' area ' + str(area_id)]
            output += net_connect.send_config_set(config_commands)
        return output
    else:
        output = ''
        device_number = 1
        address_list = string_to_list(ip_address)
        username_list = string_to_list(username)
        password_list = string_to_list(password)
        process_id_list = string_to_list(process_id)
        if len(username_list) > 1:
            for ip_address, username, password, process_id in zip(address_list, username_list, 
                                                                      password_list, process_id_list):
                output += '\nDevice #' + str(device_number) + ' configuration\n'
                net_connect = deviceConnection(ip_address, username, password)
                for network_ip, wildcard_mask in zip(network_ip_list, wildcard_mask_list):
                    config_commands = ['router ospf ' + str(process_id), 
                                    'network ' + str(network_ip) + ' ' + str(wildcard_mask) + ' area ' + str(area_id)]
                    output += net_connect.send_config_set(config_commands)
            return output
        else:
            for ip_address, process_id in zip(address_list, process_id_list):
                output += '\nDevice #' + str(device_number) + ' configuration\n'
                net_connect = deviceConnection(ip_address, username, password)
                for network_ip, wildcard_mask in zip(network_ip_list, wildcard_mask_list):
                    config_commands = ['router ospf ' + str(process_id), 
                                    'network ' + str(network_ip) + ' ' + str(wildcard_mask) + ' area ' + str(area_id)]
                    output += net_connect.send_config_set(config_commands)
            return output

def staticRouteConfig(ip_address, username, password, network_ip, network_mask, next_hop_ip):

    network_ip_list = string_to_list(network_ip)
    network_mask_list = string_to_list(network_mask)
    next_hop_list = string_to_list(next_hop_ip)
    if single_address(ip_address):
        net_connect = deviceConnection(ip_address, username, password)
        output = ''
        for network_ip, network_mask, next_hop_ip in zip(network_ip_list, network_mask_list, next_hop_list):
            config_commands = ['ip route ' + str(network_ip) + ' ' + str(network_mask) + ' ' + str(next_hop_ip)]
            output += net_connect.send_config_set(config_commands)
        return output
    else:
        output = ''
        device_number = 1
        address_list = string_to_list(ip_address)
        username_list = string_to_list(username)
        password_list = string_to_list(password)
        if len(username_list) > 1:
            for ip_address, username, password in zip(address_list, username_list, 
                                                                      password_list):
                output += '\nDevice #' + str(device_number) + ' configuration\n'
                net_connect = deviceConnection(ip_address, username, password)
                for network_ip, network_mask, next_hop_ip in zip(network_ip_list, network_mask_list, next_hop_list):
                    config_commands = ['ip route ' + str(network_ip) + ' ' + str(network_mask) + ' ' + str(next_hop_ip)]
                    output += net_connect.send_config_set(config_commands)
            return output
        else:
            for ip_address in address_list:
                output += '\nDevice #' + str(device_number) + ' configuration\n'
                net_connect = deviceConnection(ip_address, username, password)
                for network_ip, network_mask, next_hop_ip in zip(network_ip_list, network_mask_list, next_hop_list):
                    config_commands = ['ip route ' + str(network_ip) + ' ' + str(network_mask) + ' ' + str(next_hop_ip)]
                    output += net_connect.send_config_set(config_commands)
            return output

def RIPConfig(ip_address, username, password, network_ip):

    network_ip_list = string_to_list(network_ip)
    if single_address(ip_address):
        net_connect = deviceConnection(ip_address, username, password)
        output = ''
        for network_ip in network_ip_list:
            config_commands = ['router rip', 'version 2', 'network ' + str(network_ip), 'no auto-summary']
            output += net_connect.send_config_set(config_commands)
        return output
    else:
        output = ''
        device_number = 1
        address_list = string_to_list(ip_address)
        username_list = string_to_list(username)
        password_list = string_to_list(password)
        if len(username_list) > 1:
            for ip_address, username, password in zip(address_list, username_list, password_list):
                output += '\nDevice #' + str(device_number) + ' configuration\n'
                net_connect = deviceConnection(ip_address, username, password)
                for network_ip in network_ip_list:
                        config_commands = ['router rip', 'version 2', 'network ' + str(network_ip), 'no auto-summary']
                        output += net_connect.send_config_set(config_commands)
            return output
        else:
            for ip_address, in address_list:
                output += '\nDevice #' + str(device_number) + ' configuration\n'
                net_connect = deviceConnection(ip_address, username, password)
                for network_ip in network_ip_list:
                    config_commands = ['router rip', 'version 2', 'network ' + str(network_ip), 'no auto-summary']
                    output += net_connect.send_config_set(config_commands)
            return output