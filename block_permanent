import json
import sys
import paramiko
from datetime import datetime, timedelta
import time
import requests
import urllib3

host_asa = '10.41.53.253' # заменен на переменные
user_asa = 'admin' # заменен на переменные
password_asa = '1234567890' # в коде заменены на переменные
port_asa = 22 # заменен на переменные

incident = '{{tag.IDENTIFIER}}' # sys.argv[1] 
XTOKEN = '33be0503ead8909c1d1aa8f667f33971b6f6a91ca884a4208ba88bf096df5cc8' # заменен на переменные
PROTOCOL = 'http://' # заменен на переменные
RVISION = '10.22.20.140' # заменен везде на переменные


def get_cisco_info(protocol: str, rvision: str, XToken: str, incident:str) -> list:
    requests.packages.urllib3.disable_warnings()
    s = requests.Session()
    #фильтр в инцидентах заменить
    incidents = s.get(protocol + rvision + '/api/v2/incidents' + '?filter=[{\"property\":\"identifier\",\"operator\":\"=\",\"value\":\"' + incident + '\"}]',
                      headers={'X-Token': XToken},
                      verify=False)
    incidentsResult = incidents.json()
    print(incidentsResult['data']['result'][0]['cisco_integration'])
    return incidentsResult['data']['result'][0]['cisco_integration']

def send_command(cmd):
    client.send(cmd + '\n')
    time.sleep(1)
    output = client.recv(65535).decode('latin1').split('\r\n')
    return output


def get_list_of_IP(incident) -> list:
    ip_deny = []
    for i in get_cisco_info(protocol=PROTOCOL, rvision=RVISION, XToken=XTOKEN, incident= incident):
        if i['block_ip'] == True:
            ip_deny.append(i['src_address'])
    
    return ip_deny


def add_ip_to_ACL(passw, incident):
    try:
        send_command('en')
        send_command(passw)
        send_command('conf t')

        if len(get_list_of_IP(incident)) == 0:
            update_bad()
        else:
            for i in get_list_of_IP(incident):
                send_command(f'access-list TEST2 line 1 deny host {i}')
                
    except:
        None



def update_good(incident: str):
    DATA_EXPORT = get_cisco_info(protocol=PROTOCOL, rvision=RVISION, XToken=XTOKEN, incident= incident)
    DATA_IMPORT = DATA_EXPORT
    
    for i in DATA_IMPORT:
        if i[\"block_ip\"] == True:
            i[\"status_kill_session\"] = \"IP адрес заблокирован\"
    
    data = {\"identifier\": incident, \"cisco_integration\": DATA_IMPORT}
    requests.post(PROTOCOL + RVISION + \"/api/v2/incidents\", headers={\"X-Token\": XTOKEN}, data=json.dumps(data), verify=False)

def update_bad():
    DATA_EXPORT = get_cisco_info(protocol=PROTOCOL, rvision=RVISION, XToken=XTOKEN, incident=incident)
    DATA_IMPORT = DATA_EXPORT
    
    for i in DATA_IMPORT:
        if i[\"block_ip\"] == True:
            i[\"status_kill_session\"] = \"Ошибка при блокировке\"
    
    data = {\"identifier\": incident, \"cisco_integration\": DATA_IMPORT}
    requests.post(PROTOCOL + RVISION + \"/api/v2/incidents\", headers={\"X-Token\": XTOKEN}, data=json.dumps(data), verify=False)


try:
    
    client_pre = paramiko.SSHClient()
    client_pre.load_system_host_keys()
    client_pre.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client_pre.connect(hostname=host_asa, username=user_asa, password=password_asa, port=port_asa)
    client = client_pre.invoke_shell()
                #functions


    
    add_ip_to_ACL(password_asa, incident)
    update_good(incident)
    print(get_list_of_IP(incident))

    client.close()
    client_pre.close()
except:
    update_bad()
