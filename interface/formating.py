#Importación del módulo ipaddress
from ipaddress import ip_address

#Función para determinar si el usuario ingresa una sola dirección ip o varias
def single_address(adress):
    if ',' in adress:
        return False
    else:
        return True

#Función para convertir un string a una lista en caso de que envíe más de un dato en un campo
def string_to_list(string):
    string = string.replace(' ', '')
    return string.split(',')

#Función para validar una sola dirección ip
def single_address_validation(address):
    try:
        ip = ip_address(address)
        return True
    except ValueError:
        return False

#Función para validar varias direcciones ip
def multiple_address_validation(ip_addresses):
    address_list = string_to_list(ip_addresses)
    for address in address_list:
        try: 
            ip = ip_address(address)
        except ValueError:
            return False
    return True