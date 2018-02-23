#!/usr/bin/python3
import pexpect
import subprocess
import sys
import os
import re

cmd_paths = ['/usr/bin/ssh', '/usr/bin/tftp']
for a in range(len(cmd_paths)):
    if not os.path.isfile(cmd_paths[a]):
        print(cmd_paths(a) + " is not installed or in a different path, please refer to your OS document to install.")
        sys.exit(0) 

cmd_asa_port = 'show run object-group id TCP-OPEN | redirect tftp://10.2.201.59/tcp-open'
#cmd_sw_client = 'show access-lists rsp-client | redirect tftp://10.2.201.59/rsp-client'
get_asa_output = 'echo "get tcp-open" | tftp 10.2.201.59'
#get_sw_output = 'echo "get rsp-client" | tftp 10.2.201.59'
asa_ip = '10.2.40.4'
#sw_ip = '10.2.5.1'
usename = input("Please enter your login account: ")
password = input("Please enter your login password: ")
#server_ip = input("Please enter the server IP address: ")
server_port = input("Please enter the port number: ")

re_port = re.compile(r'^\d{1,5}$')
verify_port = re_port.search(server_port)
if not verify_port or not int(server_port) < 65536:
    print("Port number: " + server_port + " is invaild, please check your input.")
    sys.exit(0)
#re_ip = re.compile(r'^(\d{1,3})\.(\d){1,3}\.(\d{1,3})\.(\d{1,3})$')
#verify_ip = re_ip.search(server_ip)
#if verify_ip:
#    ip_group = verify_ip.groups()
#    for ip in ip_group:
#        if int(ip) >= 255:
#            print(server_ip + ' is not a valid IP address. Please verify your IP address')
#            sys.exit(0)
#else:
#    print('Please valid your input: ' + server_ip + " is not an IP address")
#    sys.exit(0)


def get_asa_port(_ip_):
    asa_connect = pexpect.spawnu('ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 '+ usename + '@' + (_ip_))
    #asa_connect.logfile = sys.stdout
    asa_1st_login = asa_connect.expect(['(yes/no)', 'password:'])
    if asa_1st_login == 0:
        asa_connect.sendline('yes')
    elif asa_1st_login == 1:
        asa_connect.sendline(password)
    else:
        print("Error login to firewall")
        sys.exit(0)
    asa_connect.expect('>')
    asa_connect.sendline('enable')
    asa_connect.expect('Password:')
    asa_connect.sendline(password)
    asa_connect.expect('#')
    asa_connect.sendline(cmd_asa_port)
    asa_connect.sendline("exit")
    asa_connect.close

#def get_sw_port(_ip_):
#    sw_connect = pexpect.spawnu('ssh ' + usename + '@' + str(_ip_))
#    sw_connect.logfile = sys.stdout
#    sw_1st_login = sw_connect.expect(['(yes/no)', 'Password:'])
#    if sw_1st_login == 0:
#        sw_connect.sendline("yes")
#    elif sw_1st_login == 1:
#        sw_connect.sendline(password)
#    else:
#        print("Error login to switch")
#        sys.exit(0)
#    sw_connect.expect('#')
#    sw_connect.sendline(cmd_sw_client)
#    sw_connect.sendline("exit")
#    sw_connect.close

def get_tftp(_file_):
    get_file = subprocess.call(_file_, shell=True)
    if get_file == 0:
        print("File downloaded")
        return(0)
    elif get_file == 1:
        print("Error execute command: " + _file_)
        return(1)
    else:
        print("Failed to execute command: " + _file_ + '.' + "Error code: " + get_file)
        return(get_file)

#get_sw_port(sw_ip)
get_asa_port(asa_ip)
get_tftp(get_asa_output)
#get_tftp(get_sw_output)

re_tcp_open = re.compile(r'\s+port-object\s(eq|range)\s(\d{1,5}|\w+)\s?(\d{1,5})?')

tcp_open = open('tcp-open', "r")
port_map = open('cisco-port-map.dict', "r")
port_exits = 0
for line_asa in tcp_open:
    line_asa_match = re_tcp_open.search(line_asa)
    if not line_asa_match == None:
        asa_ports = line_asa.split(' ')
#        print(asa_ports)
        if len(asa_ports) == 4 and re.match("\d{1,5}", asa_ports[3]) and server_port == asa_ports[3].replace("\n", ""):
            print("Port: " + server_port + " is not blocked by ASA")
            port_exits = 1
            break
        elif len(asa_ports) == 4 and re.match("^[a-z](\w+)?-?(\w+)?", asa_ports[3]):
            for cisco_port in port_map:
                port_name = cisco_port.split(' ')
                if server_port == port_name[1].replace("\n", ""):
                    print("Port: " + server_port + " is not blocked by ASA")
                    port_exits = 1
                    break
                break
        elif len(asa_ports) == 5 and re.match("^range$", asa_ports[2]):
            for port_range in range(int(asa_ports[3]), int(asa_ports[4].replace("\n", ""))+1):
                if int(server_port) == int(port_range):
                    print("Port: " + server_port + " is not blocked by ASA")
                    port_exits = 1
                    break
                break

if port_exits == 0:
        print("Port: " + server_port + " is blocked by Firewall")

tcp_open.close()
port_map.close()

#rsp_client = open('rsp_client', "r")
#for client_ports in rsp_client:
    
#rsp_client.close()
