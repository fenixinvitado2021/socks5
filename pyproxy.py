# -*- coding: utf-8 -*-
import socket
import select
from struct import pack, unpack
# Import Sistema
import traceback
from threading import Thread, activeCount
from signal import signal, SIGINT, SIGTERM
from time import sleep
import sys
from cfg import*
import S5Crypto

# PyProxy 1.0
print('PyProxy v2.5')


# Imprimir IP
hostname = socket.gethostname()
local_ip = socket.gethostbyname(hostname)
print(f'\nDatos:\n\nDirección: {local_ip}:{LOCAL_PORT}\n')

# Encriptado del Proxy
enc = S5Crypto.encrypt(f'{local_ip}:{LOCAL_PORT}')
proxy = f'socks5://' + enc
print(f'Encriptado: {proxy}\n')



# Parámetro para vincular un socket a un dispositivo, usando SO_BINDTODEVICE
# Solo la root puede establecer esta opción
# Si el nombre es una cadena vacía o Ninguno, la interfaz se elige cuando
# se toma una decisión de enrutamiento
# Interfaz saliente = "eth0"
OUTGOING_INTERFACE = ""

#
'''Versión del protocolo'''
# PROTOCOLO VERSIÓN 5
VER = b'\x05'
'''Method constants'''
# '00' NO SE REQUIERE AUTENTICACIÓN
M_NOAUTH = b'\x00'
# 'FF' NO HAY MÉTODOS ACEPTABLES
M_NOTAVAILABLE = b'\xff'
'''Constantes de comando'''
# CONECTAR '01'
CMD_CONNECT = b'\x01'
'''Constantes de tipo de dirección'''
# IP V4 address '01'
ATYP_IPV4 = b'\x01'
# NOMBRE DE DOMINIO '03'
ATYP_DOMAINNAME = b'\x03'


class ExitStatus:
    """ Administrar el estado de salida """
    def __init__(self):
        self.exit = False

    def set_status(self, status):
        """ establecer el estado de existencia """
        self.exit = status

    def get_status(self):
        """ obtener estado de salida """
        return self.exit


def error(msg="", err=None):
    """ Imprimir seguimiento de pila de excepción python """
    if msg:
        traceback.print_exc()
        #print("{} - Code: {}, Message: {}".format(msg, str(err[0]), err[1]))
    else:
        traceback.print_exc()


def proxy_loop(socket_src, socket_dst):
    """ Espere la actividad de la red """
    while not EXIT.get_status():
        try:
            reader, _, _ = select.select([socket_src, socket_dst], [], [], 1)
        except select.error as err:
            error("Selección fallida", err)
            return
        if not reader:
            continue
        try:
            for sock in reader:
                data = sock.recv(BUFSIZE)
                if not data:
                    return
                if sock is socket_dst:
                    socket_src.send(data)
                else:
                    socket_dst.send(data)
        except socket.error as err:
            error("Loop failed", err)
            return


def connect_to_dst(dst_addr, dst_port):
    """ Conectar al destino deseado """
    sock = create_socket()
    if OUTGOING_INTERFACE:
        try:
            sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_BINDTODEVICE,
                OUTGOING_INTERFACE.encode(),
            )
        except PermissionError as err:
            #print("Solo root puede establecer el parámetro OUTGOING_INTERFACE")
            EXIT.set_status(True)
    try:
        sock.connect((dst_addr, dst_port))
        return sock
    except socket.error as err:
        error("No se pudo conectar al DST", err)
        return 0


def request_client(wrapper):
    """ Detalles de la solicitud del cliente """
    # +----+-----+-------+------+----------+----------+
    # |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    # +----+-----+-------+------+----------+----------+
    try:
        s5_request = wrapper.recv(BUFSIZE)
    except ConnectionResetError:
        if wrapper != 0:
            wrapper.close()
        error()
        return False
    # Check VER, CMD and RSV
    if (
            s5_request[0:1] != VER or
            s5_request[1:2] != CMD_CONNECT or
            s5_request[2:3] != b'\x00'
    ):
        return False
    # IPV4
    if s5_request[3:4] == ATYP_IPV4:
        dst_addr = socket.inet_ntoa(s5_request[4:-2])
        dst_port = unpack('>H', s5_request[8:len(s5_request)])[0]
    # DOMAIN NAME
    elif s5_request[3:4] == ATYP_DOMAINNAME:
        sz_domain_name = s5_request[4]
        dst_addr = s5_request[5: 5 + sz_domain_name - len(s5_request)]
        port_to_unpack = s5_request[5 + sz_domain_name:len(s5_request)]
        dst_port = unpack('>H', port_to_unpack)[0]
    else:
        return False
    print('IP entrante:')
    print(dst_addr, dst_port)
    # guardar log en un archivo txt llamado logs.txt
    with open('logs.txt', 'a') as f:
        f.write(f'IP entrante: {dst_addr}:{dst_port}\n')
    return (dst_addr, dst_port)


def request(wrapper):
    """
       La información de solicitud de SOCKS es enviada por el cliente tan pronto como ha
       estableció una conexión con el servidor SOCKS y completó la
       negociaciones de autenticación. El servidor evalúa la solicitud y
       devuelve una respuesta
    """
    dst = request_client(wrapper)
    # Server Reply
    # +----+-----+-------+------+----------+----------+
    # |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    # +----+-----+-------+------+----------+----------+
    rep = b'\x07'
    bnd = b'\x00' + b'\x00' + b'\x00' + b'\x00' + b'\x00' + b'\x00'
    if dst:
        socket_dst = connect_to_dst(dst[0], dst[1])
    if not dst or socket_dst == 0:
        rep = b'\x01'
    else:
        rep = b'\x00'
        bnd = socket.inet_aton(socket_dst.getsockname()[0])
        bnd += pack(">H", socket_dst.getsockname()[1])
    reply = VER + rep + b'\x00' + ATYP_IPV4 + bnd
    try:
        wrapper.sendall(reply)
    except socket.error:
        if wrapper != 0:
            wrapper.close()
        return
    # start proxy
    if rep == b'\x00':
        proxy_loop(wrapper, socket_dst)
    if wrapper != 0:
        wrapper.close()
    if socket_dst != 0:
        socket_dst.close()


def subnegotiation_client(wrapper):
    """
        El cliente se conecta al servidor y envía una versión
        mensaje de selección de identificador /method
    """
    # Identificador de versión del cliente mensaje de selección de /method
    # +----+----------+----------+
    # |VER | NMETHODS | MÉTODOS  |
    # +----+----------+----------+
    try:
        identification_packet = wrapper.recv(BUFSIZE)
    except socket.error:
        error()
        return M_NOTAVAILABLE
    # VER field
    if VER != identification_packet[0:1]:
        return M_NOTAVAILABLE
    # METHODS fields
    nmethods = identification_packet[1]
    methods = identification_packet[2:]
    if len(methods) != nmethods:
        return M_NOTAVAILABLE
    for method in methods:
        if method == ord(M_NOAUTH):
            return M_NOAUTH
    return M_NOTAVAILABLE


def subnegotiation(wrapper):
    """
        El cliente se conecta al servidor y envía una versión
        mensaje de selección de identificador /method
        El servidor selecciona uno de los métodos dados en MÉTODOS, y
        envía un mensaje de selección de MÉTODO
    """
    method = subnegotiation_client(wrapper)
    # Server Method selection message
    # +----+--------+
    # |VER | METHOD |
    # +----+--------+
    if method != M_NOAUTH:
        return False
    reply = VER + method
    try:
        wrapper.sendall(reply)
    except socket.error:
        error()
        return False
    return True


def connection(wrapper):
    """ Función ejecutada por un hilo """
    if subnegotiation(wrapper):
        request(wrapper)


def create_socket():
    """ Cree un socket INET, STREAMing """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT_SOCKET)
    except socket.error as err:
        error("No se pudo crear el socket", err)
        sys.exit(0)
    return sock


def bind_port(sock):
    """
        Vincule el socket a la dirección y
        escucha las conexiones hechas al socket
    """
    try:
        #print('Puerto: {}'.format(str(LOCAL_PORT)))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((LOCAL_ADDR, LOCAL_PORT))
    except socket.error as err:
        error("Enlace fallido", err)
        sock.close()
        sys.exit(0)
    # Listen
    try:
        sock.listen(10)
    except socket.error as err:
        error("Escucha fallida", err)
        sock.close()
        sys.exit(0)
    return sock


def exit_handler(signum, frame):
    """ Manejador de señales llamado con señal, script de salida """
    #print('Manejador de señal llamado con señal', signum)
    EXIT.set_status(True)


def main():
    """ Función principal """
    new_socket = create_socket()
    bind_port(new_socket)
    signal(SIGINT, exit_handler)
    signal(SIGTERM, exit_handler)
    while not EXIT.get_status():
        if activeCount() > MAX_THREADS:
            sleep(3)
            continue
        try:
            wrapper, _ = new_socket.accept()
            wrapper.setblocking(1)
        except socket.timeout:
            continue
        except socket.error:
            error()
            continue
        except TypeError:
            error()
            sys.exit(0)
        recv_thread = Thread(target=connection, args=(wrapper, ))
        recv_thread.start()
    new_socket.close()


EXIT = ExitStatus()
if __name__ == '__main__':
    main()
