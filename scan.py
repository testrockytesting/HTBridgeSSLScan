import requests
import json

target = raw_input("Enter the domain name that you want to scan for SSL configuration : ")

headers = {}
headers['Content-Type'] = "application/x-www-form-urlencoded"

data1='domain=%s&show_test_results=false&recheck=false&verbosity=1' %target
req1 = requests.post('https://www.htbridge.com/ssl/api/v1/check/0000000001.html', headers=headers , data=data1)
result1 = req1.json()
print result1
selectedIP = result1['multiple_ips'][0]
token = result1['token']

data2 = 'domain=%s&show_test_results=false&recheck=false&choosen_ip=%s&verbosity=1&token=%s' % (target,selectedIP, token)
req2 = requests.post('https://www.htbridge.com/ssl/api/v1/check/0000000001.html', headers=headers , data=data2)
result2 = req2.json()
