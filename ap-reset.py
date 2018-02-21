#!/usr/bin/python3
import pexpect
import time
import sys
import re

#This script is designed by Chandler Wong from ReSource Pro to reboot all access points registered on certain WLC. It may have risks to run in production during working hours.
def ip_warning(user_input):
	print("Invalid IP address " + user_input + ", Please check your input.")
	sys.exit(0)

def ap_lookup(ap_line):
	ap_finder = re.compile(r'(^[\w\d]*-.*)(\s*)(\d)(\s*)(AIR-\w?AP)')
	ap_name = ap_finder.search(ap_line)
	if ap_name:
		return(ap_name.group(1))

aps=[]
username = input("Input your username: ")
password = input("Input your password: ")
wlc_ip = input("Which WLC do you want to connect: ")

re_ip = re.compile(r'(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})')
re_ip_exception = re.compile(r'(\d{1,3}\.){4,}')

if re_ip_exception.search(wlc_ip):
	ip_warning(wlc_ip)

verify_ip = re_ip.search(wlc_ip)

if verify_ip:
	ip_group = verify_ip.groups()
	for ip in ip_group:
		if int(ip) >= 255:
			ip_warning(wlc_ip)
else:
	ip_warning(wlc_ip)

wlc_connect = pexpect.spawnu('ssh ' +  wlc_ip)
#wlc_connect.logfile = sys.stdout
wlc_connect.expect('User:')
wlc_connect.sendline(username)
wlc_connect.expect('Password:')
wlc_connect.sendline(password)

login_check = wlc_connect.expect(['(Cisco Controller)', 'User'])
if login_check == 1:
	print("Login Error, Check your account status")
	sys.exit(0)
else:
	print("Login Successfully")

wlc_connect.sendline('show ap summary')

while True:
	next_page = wlc_connect.expect(['--More', '(Cisco Controller)'])
	if next_page == 0:
		ap_wlc = wlc_connect.before
		for ap_inline in ap_wlc.splitlines():
			ap_name = ap_lookup(ap_inline)
			if ap_name:
				aps.append(ap_name)
		wlc_connect.sendline('')
	elif next_page == 1:
		break

ap_wlc = wlc_connect.before

for ap_inline in ap_wlc.splitlines():
	ap_name = ap_lookup(ap_inline)
	if ap_name:
		aps.append(ap_name)

for ap in range(len(aps)):
	wlc_connect.sendline('config ap reset ' + aps[ap])
	wlc_connect.expect('Would you like to reset')
	wlc_connect.sendline('y')
	time.sleep(10)

wlc_connect.sendline('logout')

logout_wlc = wlc_connect.expect(['y/N', pexpect.EOF])

if logout_wlc == 0:
	wlc_connect.sendline("N")

wlc_connect.close()
