#!/usr/bin/python3
import pexpect
import sys

cmd_asa_port = 'show run object-group id TCP-OPEN | redirect tftp://10.2.201.59/tcp-open'
cmd_sw_client = 'show access-lists rsp-client | redirect tftp://10.2.201.59/rsp-client'
asa_ip = '10.2.40.4'
sw_ip = '10.2.5.1'
usename = input("Please enter your login account: ")
password = input("Please enter your login password: ")
server_ip = input("Please enter the server IP address: ")
server_port = input("Please enter the port number: ")

#ports = []

def get_asa_port(_ip_):
    asa_connect = pexpect.spawnu('ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 '+ usename + '@' + (_ip_))
    asa_connect.logfile = sys.stdout
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
    asa_connect.sendline('r11t123~')
    asa_connect.expect('#')
    asa_connect.sendline(cmd_asa_port)
    asa_connect.sendline("exit")
    asa_connect.close

def get_sw_port(_ip_):
    sw_connect = pexpect.spawnu('ssh ' + usename + '@' + str(_ip_))
    sw_connect.logfile = sys.stdout
    sw_1st_login = sw_connect.expect(['(yes/no)', 'Password:'])
    if sw_1st_login == 0:
        sw_connect.sendline("yes")
    elif sw_1st_login == 1:
        sw_connect.sendline(password)
    else:
        print("Error login to switch")
        sys.exit(0)
    sw_connect.expect('#')
    sw_connect.sendline(cmd_sw_client)
    sw_connect.sendline("exit")
    sw_connect.close

get_sw_port(sw_ip)
get_asa_port(asa_ip)

