import sys
import paramiko
from datetime import datetime, timedelta
import time
import requests
import urllib3

host_asa = sys.argv[1] # '10.41.53.253'  заменен на переменные sys.argv[1]
user_asa = sys.argv[2] #'admin'  заменен на переменные sys.argv[2]
password_asa = sys.argv[3] #'1234567890' в коде заменены на переменные sys.argv[3]
port_asa = sys.argv[4] #22 заменен на переменные sys.argv[4]

incident = sys.argv[5] #'{{tag.IDENTIFIER}}'  sys.argv[5] 
XTOKEN = sys.argv[6] #'78479506a4173b34305b9168ea15b71a839cadca3698dc70185f3c742f58032d' заменен на переменные sys.argv[6]
PROTOCOL = sys.argv[7] # 'http://' заменен на переменные sys.argv[7]
RVISION = sys.argv[8] # '10.22.20.140' заменен везде на переменные sys.argv[8]


def get_cisco_info(protocol: str, rvision: str, XToken: str, incident:str) -> list:
    requests.packages.urllib3.disable_warnings()
    s = requests.Session()
    #фильтр в инцидентах заменить
    incidents = s.get(protocol + rvision + '/api/v2/incidents' + '?filter=[{\"property\":\"identifier\",\"operator\":\"=\",\"value\":\"' + incident + '\"}]',
                      headers={'X-Token': XToken},
                      verify=False)
    incidentsResult = incidents.json()
    return incidentsResult['data']['result'][0]['cisco_integration']

def extract_ip_addresses(text):
    # Регулярное выражение для поиска IP-адресов
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    # Поиск всех IP-адресов в строке
    ip_addresses = re.findall(ip_pattern, text)
    # Фильтруем только валидные IP-адреса (0-255 для каждого октета)
    valid_ips = [ip for ip in ip_addresses if all(0 <= int(octet) <= 255 for octet in ip.split('.'))]
    return valid_ips

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

def get_start_time(passw) -> str:
    send_command('en')
    send_command(passw)
    ACL = send_command('sh clock')
    return ACL


def add_time_range(min: int, passw: str, incident: str):
    send_command('en')
    send_command(passw)
    send_command('conf t')
    send_command('time-range {a} \n absolute end {s}'.format(a = incident, s= add_minutes(get_start_time(passw)[1], min)))

def add_minutes(input_string, minutes_to_add):
    dt = datetime.strptime(input_string, '%H:%M:%S.%f UTC %a %b %d %Y')
    updated_dt = dt + timedelta(minutes=minutes_to_add)
    return updated_dt.strftime('%H:%M %d %b %Y')

def add_ip_to_ACL(passw, incident):
    try:
        send_command('en')
        send_command(passw)
        send_command('conf t')

        if len(get_list_of_IP(incident)) == 0:
            update_bad()
        else:
            for i in get_list_of_IP(incident):
                send_command(f'access-list TEST2 line 1 extended deny ip host {i} any time-range {incident}') #подумать
                send_command(f'access-list PC2 line 1 extended deny ip any host {i} time-range {incident}')
    except:
        None


def show_time_range(passw) -> list:
    send_command('en')
    send_command(passw)
    return send_command('sh time-range')

def show_ACL(passw) -> list:
    send_command('en')
    send_command(passw)
    ACL = send_command('sh access-list')
    return ACL


def delete_time_range(passw):
    send_command('en')
    send_command(passw)
    send_command('conf t')
    time_range = send_command('sh time-range')
    if any('(active)' in i.lower().split() for i in time_range):
        return None
    else:
        send_command('clear configur time-range')


def delete_from_ACL_first(passw):

    data_time_range = show_time_range(passw)
    counter = 0
    for i in data_time_range:
        if '(active)' in i:
            counter += 1

    if counter == 0:
        for i in show_ACL(passw):
            if '224' in i and '(inactive)' in i: # 224 название ACL поменять на нужный
                send_command('en')
                send_command(passw)
                send_command('conf t')
                rez = extract_ip_addresses(i) #no access-list 224 line 1 extended deny ip host rez[0] any time-range 225
                send_command(f'no access-list 224 extended deny ip host {rez[0]} any')
        delete_time_range(passw)
    else:
        return None



def update_good(incident: str):
    DATA_EXPORT = get_cisco_info(protocol=PROTOCOL, rvision=RVISION, XToken=XTOKEN, incident= incident)
    DATA_IMPORT = DATA_EXPORT
    
    for i in DATA_IMPORT:
        if i['block_ip'] == True:
            i['status_kill_session'] = 'IP адрес заблокирован'
    
    data = {'identifier': incident, 'cisco_integration': DATA_IMPORT}
    requests.post(PROTOCOL + RVISION + '/api/v2/incidents', headers={'X-Token': XTOKEN}, data=json.dumps(data), verify=False)

def update_bad():
    DATA_EXPORT = get_cisco_info(protocol=PROTOCOL, rvision=RVISION, XToken=XTOKEN, incident=incident)
    DATA_IMPORT = DATA_EXPORT
    
    for i in DATA_IMPORT:
        if i['block_ip'] == True:
            i['status_kill_session'] = 'Ошибка при блокировке'
    
    data = {'identifier': incident, 'cisco_integration': DATA_IMPORT}
    requests.post(PROTOCOL + RVISION + '/api/v2/incidents', headers={'X-Token': XTOKEN}, data=json.dumps(data), verify=False)


try:
    a = 5 # время блокировки

    client_pre = paramiko.SSHClient()
    client_pre.load_system_host_keys()
    client_pre.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client_pre.connect(hostname=host_asa, username=user_asa, password=password_asa, port=port_asa)
    client = client_pre.invoke_shell()
                #functions
    delete_from_ACL_first(password_asa) #надо проверить
    
    add_time_range(a, password_asa, incident)
    add_ip_to_ACL(password_asa, incident)
    update_good(incident)
    

    client.close()
    client_pre.close()
except:
    update_bad()
