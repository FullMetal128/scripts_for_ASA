
import json
import sys
import paramiko
import datetime
import time
import requests
import urllib3

host_asa = '10.41.53.253'
user_asa = 'admin'
password_asa = '1234567890'
port_asa = 22

ip_rvision = '10.22.20.140'
XTOKEN = '78479506a4173b34305b9168ea15b71a839cadca3698dc70185f3c742f58032d'
PROTOCOL = 'http://'
FILTER = '?filter=[{\"property\":\"identifier\",\"operator\":\"=\",\"value\":\"{{tag.IDENTIFIER}}\"}]' 
RVISION = '10.22.20.140'


def send_command(cmd):
    client.send(cmd + '\n')
    time.sleep(1)
    output = client.recv(65535).decode('latin1').split('\r\n')
    return output

def get_cisco_info(protocol: str, rvision: str, XToken: str, incident:str) -> list:
    requests.packages.urllib3.disable_warnings()
    s = requests.Session()
    incidents = s.get(protocol + rvision + '/api/v2/incidents' + FILTER,
                      headers={'X-Token': XToken},
                      verify=False)
    incidentsResult = incidents.json()
    return incidentsResult['data']['result'][0]['cisco_integration']

def get_list_of_IP() -> list:
    ip_deny = []
    for i in get_cisco_info(protocol=PROTOCOL, rvision=RVISION, XToken=XTOKEN, incident=\"{{tag.IDENTIFIER}}\"):
        if i['block_ip'] == True:
            ip_deny.append(i['src_address'])
    return ip_deny

def delete_from_ACL(): # для удобства, потом переделать функцию под нужный список IP
    send_command('en')
    send_command('1234567890')
    send_command('conf t')
    for i in get_list_of_IP():
        send_command(f'no access-list TEST2 extended deny ip host {i} any')
        send_command(f'no access-list PC2 extended deny ip any host {i}')

def update_good():
    DATA_EXPORT = get_cisco_info(protocol=PROTOCOL, rvision=RVISION, XToken=XTOKEN, incident=\"{{tag.IDENTIFIER}}\")
    DATA_IMPORT = DATA_EXPORT
    
    for i in DATA_IMPORT:
        if i[\"block_ip\"] == True:
            i[\"status_kill_session\"] = \"IP адрес разблокирован\"
    
    data = {\"identifier\": \"{{tag.IDENTIFIER}}\", \"cisco_integration\": DATA_IMPORT}
    requests.post(PROTOCOL + RVISION + \"/api/v2/incidents\", headers={\"X-Token\": XTOKEN}, data=json.dumps(data), verify=False)

def update_bad():
    DATA_EXPORT = get_cisco_info(protocol=PROTOCOL, rvision=RVISION, XToken=XTOKEN, incident=\"{{tag.IDENTIFIER}}\")
    DATA_IMPORT = DATA_EXPORT
    
    for i in DATA_IMPORT:
        if i[\"block_ip\"] == True:
            i[\"status_kill_session\"] = \"Ошибка при разблокировке\"
    
    data = {\"identifier\": \"{{tag.IDENTIFIER}}\", \"cisco_integration\": DATA_IMPORT}
    requests.post(PROTOCOL + RVISION + \"/api/v2/incidents\", headers={\"X-Token\": XTOKEN}, data=json.dumps(data), verify=False)

try:

    client_pre = paramiko.SSHClient()
    client_pre.load_system_host_keys()
    client_pre.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client_pre.connect(hostname=host_asa, username=user_asa, password=password_asa, port=port_asa)
    client = client_pre.invoke_shell()
                #functions


    delete_from_ACL()
    update_good()
    

    client.close()
    client_pre.close()
except:
    update_bad()



