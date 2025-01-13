
import json
import sys
import paramiko
import datetime
import time
import requests
import urllib3
import re

host_asa = '10.41.53.253'
user_asa = 'admin'
password_asa = '1234567890'
port_asa = 22


ip_rvision = '10.22.20.140'
XTOKEN = '78479506a4173b34305b9168ea15b71a839cadca3698dc70185f3c742f58032d'
PROTOCOL = 'http://'
FILTER = '?filter=[{\"property\":\"identifier\",\"operator\":\"=\",\"value\":\"{{tag.IDENTIFIER}}\"}]' 
RVISION = '10.22.20.140'


def get_cisco_info(protocol: str, rvision: str, XToken: str, incident:str) -> list:
    requests.packages.urllib3.disable_warnings()
    s = requests.Session()
    
    incidents = s.get(protocol + rvision + '/api/v2/incidents' + FILTER,
                      headers={'X-Token': XToken},
                      verify=False)
    incidentsResult = incidents.json()
    return incidentsResult

def update_good():
    DATA_EXPORT = get_cisco_info(protocol=PROTOCOL, rvision=RVISION, XToken=XTOKEN, incident=\"{{tag.IDENTIFIER}}\")[\"data\"][\"result\"][0][\"blocked_hosts_list\"]
    DATA_IMPORT = DATA_EXPORT
    if len(str_IPs()) != 0:
        DATA_IMPORT = str_IPs()
        data = {\"identifier\": \"{{tag.IDENTIFIER}}\", \"blocked_hosts_list\": DATA_IMPORT}  
        requests.post(PROTOCOL + RVISION + \"/api/v2/incidents\", headers={\"X-Token\": XTOKEN}, data=json.dumps(data), verify=False)
    else:
        DATA_IMPORT = \"Нет заблокированных IP адресов\"
        data = {\"identifier\": \"{{tag.IDENTIFIER}}\", \"blocked_hosts_list\": DATA_IMPORT}  
        requests.post(PROTOCOL + RVISION + \"/api/v2/incidents\", headers={\"X-Token\": XTOKEN}, data=json.dumps(data), verify=False)


def update_bad():
    DATA_EXPORT = get_cisco_info(protocol=PROTOCOL, rvision=RVISION, XToken=XTOKEN, incident=\"{{tag.IDENTIFIER}}\")[\"data\"][\"result\"][0][\"blocked_hosts_list\"]
    DATA_IMPORT = DATA_EXPORT
    DATA_IMPORT = \"Ошибка при заполнении списка IP\"
    data = {\"identifier\": \"{{tag.IDENTIFIER}}\", \"blocked_hosts_list\": DATA_IMPORT}  
    requests.post(PROTOCOL + RVISION + \"/api/v2/incidents\", headers={\"X-Token\": XTOKEN}, data=json.dumps(data), verify=False)

def send_command(cmd):
    client.send(cmd + \"\n\")
    time.sleep(1)
    output = client.recv(65535).decode(\"latin1\").split(\"\r\n\")
    return output

def get_ACL() -> str:
    send_command('en')
    send_command('1234567890')
    ACL = send_command('sh access-list')
    return ACL

def extract_ip_addresses(text) -> str:
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ip_addresses = re.findall(ip_pattern, text)
    valid_ips = [ip for ip in ip_addresses if all(0 <= int(octet) <= 255 for octet in ip.split('.'))]
    return valid_ips

def str_IPs() -> str:
    a = []
    for i in get_ACL():
        if '(inactive)' not in i:
            b = extract_ip_addresses(i)
            if len(b) > 0 and b[0] not in a:
                a.append(b[0])
    return ' '.join(a)

try:
    client_pre = paramiko.SSHClient()
    client_pre.load_system_host_keys()
    client_pre.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client_pre.connect(hostname=host_asa, username=user_asa, password=password_asa, port=port_asa)
    client = client_pre.invoke_shell()
            #functions

    update_good()


    client.close()
    client_pre.close()
except:
    update_bad()


