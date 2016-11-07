import requests
import json


target = raw_input("\n\nEnter the domain name that you want to scan for SSL configuration : ")

headers = {}
headers['Content-Type'] = "application/x-www-form-urlencoded"


data1='domain=%s&show_test_results=false&recheck=false&verbosity=1' %target

req1 = requests.post('https://www.htbridge.com/ssl/api/v1/check/0000000001.html', headers=headers , data=data1)
result1 = req1.json()
#print result1

# Checking if the server returned multiple IPs
try:
    result1['internals']
    finalresult = json.dumps(result1, indent=4, separators=(',', ':'))

except:
    selectedIP = result1['multiple_ips'][0]
    token = result1['token']
    data2 = 'domain=%s&show_test_results=false&recheck=false&choosen_ip=%s&verbosity=1&token=%s' % (target, selectedIP, token)
    req2 = requests.post('https://www.htbridge.com/ssl/api/v1/check/0000000001.html', headers=headers, data=data2)
    result2 = req2.json()
    finalresult = json.dumps(result2, indent=4, separators=(',', ':'))

resp_dict = json.loads(finalresult)

# Printing the result of the SSL test

print "\n"
print "***********************************************************************"
print "\n\t\t\tThe analysis of SSL is as follows :\n"
print "***********************************************************************"
print "\nHTTP Header analysis : "

try:
    print "HSTS Duration : ", resp_dict['industry_best_practices']['hsts_duration']['value']
except:
    print "No HSTS info"
try:
    print "Server Info : ", resp_dict['internals']['http_headers']['http_headers']['Server']['highlight']
except:
    print "No server info"
try:
    resp_dict['internals']['http_headers']['http_headers']['X-Frame-Options']['raw']
    print "X-Frame-Options : ", resp_dict['internals']['http_headers']['http_headers']['X-Frame-Options']['raw']
except:
    print "X-Frame-Options : ", resp_dict['internals']['http_headers']['http_headers']['X-Frame-Options']['highlight']
try:
    resp_dict['internals']['http_headers']['http_headers']['X-Content-Type-Options']['raw']
    print "X-Content-Type-Options : ", resp_dict['internals']['http_headers']['http_headers']['X-Content-Type-Options']['raw']
except:
    print "X-Content-Type-Options : ", resp_dict['internals']['http_headers']['http_headers']['X-Content-Type-Options']['highlight']
try:
    resp_dict["internals"]["http_headers"]["http_headers"]["X-XSS-Protection"]["raw"]
    print "X-XSS-Protection : ", resp_dict["internals"]["http_headers"]["http_headers"]["X-XSS-Protection"]["raw"]
except:
    print "X-XSS-Protection : ", resp_dict["internals"]["http_headers"]["http_headers"]["X-XSS-Protection"]["highlight"]
print "HPKP : ", resp_dict['internals']['http_headers']['http_headers']['Public-Key-Pins']['highlight']

print "\nTesting against known vulnerabilities in OpenSSL : "
print "\ncve_2016_2107 : ", resp_dict['pci_dss']['cve_2016_2107']['message']
print "cve_2014_0224 : ", resp_dict['pci_dss']['cve_2014_0224']['message']
print "drown : ", resp_dict['pci_dss']['drown']['message']
print "poodle_tls : ", resp_dict['pci_dss']['poodle_tls']['message']
print "heartbleed : ", resp_dict['pci_dss']['heartbleed']['message']
print "supports_insecure_reneg : ", resp_dict['pci_dss']['supports_insecure_reneg']['message']
print "poodle_ssl : ", resp_dict['pci_dss']['poodle_ssl']['message']

print "\nsupported_protocols : "
for i in range(len(resp_dict['pci_dss']['supported_protocols'])):
    print resp_dict['pci_dss']['supported_protocols'][i]['value']

print "\nsupported_elliptic_curves : "
for i in range(len(resp_dict['pci_dss']['supported_elliptic_curves'])):
    print resp_dict['pci_dss']['supported_elliptic_curves'][i]['value']

print "\nsupported_cipher_suites : "
for i in range(len(resp_dict['pci_dss']['supported_cipher_suites'])):
    print resp_dict['pci_dss']['supported_cipher_suites'][i]['value']

# Analysing the SSL configuration based on Mozilla Server Security Guidelines
