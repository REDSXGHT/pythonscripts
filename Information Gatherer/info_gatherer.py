#python version 3.9 is suited 

import ipaddress
import sys
import whois
import shodan
import requests
import dns.resolver
import argparse
import re
import socket

#info
argparse = argparse.ArgumentParser(description="simple info gathering tool on python.", usage="python3 info_gatherer.py -d DOMAIN [-s IP -a SHODAN API][-o file] ")
argparse.add_argument("-d","--domain",help="Enter the Domain for footprint")
argparse.add_argument("-s","--shodan",help="Enter the IP for shodan search")
argparse.add_argument("-a","--api",help="Enter Shodan API for shodan search required when using shodan")
argparse.add_argument("-o","--output",help="Enter File name to Save")
regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"

#parsing
args = argparse.parse_args()
domain = args.domain
ip = args.shodan
apt = args.api
output = args.output

print("\n[+] Domain {}, IP {} , API {} \n \n" .format(domain,ip,apt))


#whois module
whois_res=''
whois_res+= "[+] Whois Information of {}" .format(domain) +'\n'
try:
    whs=whois.query(domain)
    if whs is None:
        whois_res+="[+] whois info not found for domain {}." .format(domain)+'\n'
    else:
        whois_res+="   ->Name               : {}".format(whs.name)+'\n'
        whois_res+="   ->Registrar          : {}".format(whs.registrar)+'\n'
        whois_res+="   ->Creation Date      : {}".format(whs.creation_date)+'\n'
        whois_res+="   ->Expiration Date    : {}".format(whs.expiration_date)+'\n'
        for name in whs.name_servers:
            whois_res+="   ->Name Servers       : {}".format(name)+'\n'
        whois_res+="   ->Registrant         : {}".format(whs.registrant)+'\n'
        whois_res+="   ->Registrant Country : {}".format(whs.registrant_country)+'\n'


except:
    pass
print(whois_res)


#DNS module
dns_res=''
dns_res+="[+] DNS info of {}" .format(domain)+'\n'
try:
    for a in dns.resolver.resolve(domain,'A'):
        dns_res+="   -> A Record     : {}" .format(a.to_text())+'\n'
    for ns in dns.resolver.resolve(domain, 'NS'):
        dns_res+="   -> NS Record    : {}".format(ns.to_text())+'\n'
    for mx in dns.resolver.resolve(domain, 'MX'):
        dns_res+="   -> MX Record    : {}".format(mx.to_text())+'\n'
    for txt in dns.resolver.resolve(domain, 'txt'):
        dns_res+="   -> TXT Record   : {}".format(txt.to_text())+'\n'
except:
    pass
print(dns_res)


#Geolocation Module
geo_res=''
geo_res+="[+] Geolocation info of {}" .format(domain)+'\n'
try:
    response = requests.request("GET","https://geolocation-db.com/json/"+socket.gethostbyname(domain)).json()
    geo_res+="   ->Country Name : {}" .format(response['country_name'])+'\n'
    geo_res+="   ->State Name   : {}" .format(response['state'])+'\n'
    geo_res+="   ->City Name    : {}" .format(response['city'])+'\n'
    geo_res+="   ->Postal Code  : {}".format(response['city']) + '\n'
    geo_res+="   ->Longitude    : {}" .format(response['longitude'])+'\n'
    geo_res+="   ->Latitude     : {}" .format(response['latitude'])+'\n'
    geo_res+="   ->IPv4         : {}" .format(response['IPv4'])+'\n'
except:
    pass
print(geo_res)


#shodan module
if ip:
    shodan_res=''
    api=shodan.Shodan(apt)
    if not re.search(regex, ip):
        p = socket.gethostbyname(ip)
    else:
        p = ip
    shodan_res += "[+] Shodan info of domain : {} resolved to ip : {}".format(ip,p) + '\n'
    try:
        results= api.search(p)
        shodan_res+="   -> Results found: {}" .format(results['total'])+'\n'
        for result in results['matches']:
            shodan_res+="      -> IP: {}".format(result['ip_str'])+'\n'
            shodan_res+="      -> Data: \n{}".format(result['data'])+'\n '
            shodan_res+="===================================================================================\n "+'\n'
            print()
    except:
        shodan_res+="[-] Shodan Search Error."+'\n'
if ip:
    print(shodan_res)


if output:
    with open(output, 'w') as file:
        file.write(whois_res+'\n')
        file.write(dns_res+'\n')
        file.write(geo_res+'\n')
        file.write(shodan_res)

