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

XTOKEN = '78479506a4173b34305b9168ea15b71a839cadca3698dc70185f3c742f58032d'
PROTOCOL = 'http://'
FILTER = '?filter=[{\"property\":\"identifier\",\"operator\":\"=\",\"value\":\"{{tag.IDENTIFIER}}\"}]' 
RVISION = '10.22.20.140'

#'?filter=[{\"property\":\"identifier\",\"operator\":\"=\",\"value\":\"{{tag.IDENTIFIER}}\"}]'

def get_cisco_info(protocol: str, rvision: str, XToken: str, incident:str) -> list:
    requests.packages.urllib3.disable_warnings()
    s = requests.Session()
    #фильтр в инцидентах заменить
    incidents = s.get(protocol + rvision + '/api/v2/incidents' + FILTER,
                      headers={'X-Token': XToken},
                      verify=False)
    incidentsResult = incidents.json()
    return incidentsResult['data']['result'][0]['cisco_integration']

def send_command(cmd):
    client.send(cmd + '\n')
    time.sleep(1)
    output = client.recv(65535).decode('latin1').split('\r\n')
    return output


def get_list_of_IP() -> list:
    ip_deny = []
    for i in get_cisco_info(protocol=PROTOCOL, rvision=RVISION, XToken=XTOKEN, incident=\"{{tag.IDENTIFIER}}\"):
        if i['block_ip'] == True:
            ip_deny.append(i['src_address'])
    return ip_deny

def get_start_time(passw) -> str:
    send_command('en')
    send_command(passw)
    ACL = send_command('sh clock')
    return ACL


def add_time_range(min: int, passw: str):
    send_command('en')
    send_command(passw)
    send_command('conf t')
    send_command('time-range {{tag.IDENTIFIER}} \n absolute end {s}'.format(s = add_minutes(get_start_time(passw)[1], min)))

def add_minutes(input_string, minutes_to_add):
    dt = datetime.strptime(input_string, '%H:%M:%S.%f UTC %a %b %d %Y')
    updated_dt = dt + timedelta(minutes=minutes_to_add)
    return updated_dt.strftime('%H:%M %d %b %Y')

def add_ip_to_ACL(passw):
    try:
        send_command('en')
        send_command(passw)
        send_command('conf t')

        if len(get_list_of_IP()) == 0:
            update_bad()
        else:
            for i in get_list_of_IP():
                send_command(f'access-list TEST2 line 1 extended deny ip host {i} any time-range {{tag.IDENTIFIER}}')
                send_command(f'access-list PC2 line 1 extended deny ip any host {i} time-range {{tag.IDENTIFIER}}')
    except:
        None


def show_ACL(passw) -> list:
    send_command('en')
    send_command(passw)
    ACL = send_command('sh access-list')
    return ACL


def delete_time_range(passw):
    send_command('en')
    send_command(passw)
    send_command('conf t')
    send_command('clear configur time-range')



def update_good():
    DATA_EXPORT = get_cisco_info(protocol=PROTOCOL, rvision=RVISION, XToken=XTOKEN, incident=\"{{tag.IDENTIFIER}}\")
    DATA_IMPORT = DATA_EXPORT
    
    for i in DATA_IMPORT:
        if i[\"block_ip\"] == True:
            i[\"status_kill_session\"] = \"IP адрес заблокирован\"
    
    data = {\"identifier\": \"{{tag.IDENTIFIER}}\", \"cisco_integration\": DATA_IMPORT}
    requests.post(PROTOCOL + RVISION + \"/api/v2/incidents\", headers={\"X-Token\": XTOKEN}, data=json.dumps(data), verify=False)

def update_bad():
    DATA_EXPORT = get_cisco_info(protocol=PROTOCOL, rvision=RVISION, XToken=XTOKEN, incident=\"{{tag.IDENTIFIER}}\")
    DATA_IMPORT = DATA_EXPORT
    
    for i in DATA_IMPORT:
        if i[\"block_ip\"] == True:
            i[\"status_kill_session\"] = \"Ошибка при блокировке\"
    
    data = {\"identifier\": \"{{tag.IDENTIFIER}}\", \"cisco_integration\": DATA_IMPORT}
    requests.post(PROTOCOL + RVISION + \"/api/v2/incidents\", headers={\"X-Token\": XTOKEN}, data=json.dumps(data), verify=False)


try:
    a = 5 # время блокировки

    client_pre = paramiko.SSHClient()
    client_pre.load_system_host_keys()
    client_pre.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client_pre.connect(hostname=host_asa, username=user_asa, password=password_asa, port=port_asa)
    client = client_pre.invoke_shell()
                #functions


    add_time_range(a, password_asa)
    add_ip_to_ACL(password_asa)
    update_good()
    

    client.close()
    client_pre.close()
except:
    update_bad()
