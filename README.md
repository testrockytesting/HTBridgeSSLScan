# HTBridgeSSLScan
Python script for invoking SSL Scan through HTBridge API 

This python script can be used to scan any domain for SSL configuration. It uses HTBridge SSL test API. You can read about the documentation of the API at https://www.htbridge.com/ssl/SSL_API_guide_v1.0.pdf

Currently the output shows following items:
- HTTP header analysis
- Vulnerabilities in SSL implementation
- Protocols supported
- Cipher Suites supported 

Things to do 
- Beautify the JSON output(done) and present in html/pdf report 
- Compare it with Mozilla Server security standard and give recommendation 
