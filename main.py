import json
import os
import subprocess
import datetime
from clickhouse_driver import Client
from secret import secret_CH


def ch_connect():  # Make try/except
    client = Client(secret_CH['ip'],
                    port=secret_CH['port'],
                    user=secret_CH['user'],
                    password=secret_CH['password'],
                    verify=False,
                    database=secret_CH['db']
                    )
    return client


def scan_top50(input_ips_f_name):
    command = [
        'sudo',
        'nmap',
        '-sS',
        '-T4',
        '--top-ports',
        '50',
        '-iL',
        './source_ips/' + input_ips_f_name,
        '--min-parallelism',
        '2048',
        '-oN',
        './source_ips/top50_ports_for_all_ips'
    ]
    # print(command)
    scan = subprocess.Popen(command)
    scan.wait()
    # print(f_name)


def get_ip_blocks(path):
    with open(path, 'r') as file:
        file_strings = file.readlines()

    valid_strings = []
    for i in range(0, len(file_strings)):
        if file_strings[i].find('Increasing') != -1 or file_strings[i].find('Warning') != -1:
            continue
        else:
            valid_strings.append(file_strings[i])

    entry_point = 0
    for i in range(0, len(valid_strings)):
        if valid_strings[i].find('Nmap scan report') != -1:
            entry_point = i
            break

    ip_blocks = []
    current_ip_block = []
    for i in range(entry_point, len(valid_strings)):
        if valid_strings[i] != '\n':
            current_ip_block.append(valid_strings[i])
        else:
            if len(current_ip_block) > 3:
                ip_blocks.append(current_ip_block)
            current_ip_block = []
    # print(ip_blocks)
    return ip_blocks


def get_vulnerable_ips(f_name):
    ips = []
    ip_blocks = get_ip_blocks('./source_ips/' + f_name)
    for block in ip_blocks:
        ips.append(block[0][block[0].rfind(' '):].strip(' )(\n'))
    for i in range(0, len(ips), 10):
        last_index = i + 10
        if i + 10 > len(ips) - 1:
            last_index = len(ips) - 1
        with open('./vulnerable_ips/vulnerable_pack_' + str(i//10), 'w') as w_file:
            for j in range(i, last_index):
                w_file.write(ips[j] + '\n')
    return ips


def scan_vulnerable_ips(f_name):
    command = [
        'sudo',
        'nmap',
        '-sS',
        '-T4',
        '-Pn',
        '-p-',
        '-iL',
        './vulnerable_ips/' + f_name,
        '-v',
        '--min-hostgroup',
        '10',
        '--max-hostgroup',
        '10',
        '--min-parallelism',
        '2048',
        '-oN',
        './nmap_results/res_' + f_name
    ]
    print(command)
    scan = subprocess.Popen(command)
    scan.wait()


def get_tenant_info(ip):
    tenant_name = ''
    tenant_id = 9999
    tenant_dict_file = json.load(open('result_with_tenant.json'))
    # print(tenant_dict_file)
    for tenant in tenant_dict_file.values():
        if ip in tenant['ips']:
            # print(tenant)
            tenant_name = tenant['tenant']
            tenant_id = tenant['tenant_id']

    return tenant_name, tenant_id


def get_parsed_block(ip_block):
    domain = None
    if ip_block[0].find('.ru') != -1:
        domain_end = ip_block[0].rfind(' ')
        domain_start = ip_block[0].rfind(' ', 0, domain_end)
        domain = ip_block[0][domain_start:domain_end].strip()
    ip = ip_block[0][ip_block[0].rfind(' '):].strip('() \n')

    # ports = []
    # port_state = {}
    # port_service = {}
    parsed_block = []
    for i in range(4, len(ip_block)):
        port = int(ip_block[i][0:ip_block[i].find('/')])
        state = ip_block[i][ip_block[i].find(' '):ip_block[i].rfind(' ')].strip()
        if state == 'closed':
            continue

        service = ip_block[i][ip_block[i].rfind(' '):].strip()
        banner = None
        version = None
        tenant, tenant_id = get_tenant_info(ip)

        parsed_block.append({
            'ip': ip,
            'port': port,
            'state': state,
            'service': service,
            'banner': banner,
            'version': version,
            'domain': domain,
            'tenant': tenant,
            'tenant_id': tenant_id
        })

        # port_state[port] = state
        # port_service[port] = service
        # ports.append(int(port))
    # return [ip, ports, port_state, port_service]
    return parsed_block


def parse_nmap_result_file(f_name):
    ip_blocks = get_ip_blocks('./nmap_results/' + f_name)
    parsed_ip_blocks = []
    for ip_block in ip_blocks:
        # print(ip_block)
        parsed_block = get_parsed_block(ip_block)
        if parsed_block:
            parsed_ip_blocks.append(parsed_block)

    # for el in parsed_ip_blocks:
    #     for e in el:
    #         print(e)
    #     print(el)
    return parsed_ip_blocks


def load_data_to_ch(parsed_data):
    client = ch_connect()
    for el in parsed_data:
        # print(el)
        for rec in el:
            # print(rec)
            client.execute('INSERT INTO internet (*) VALUES',
                           [(
                               # datetime.date(year, month, day),
                               # datetime.date(2021, 11, 26),
                               datetime.datetime.now().date(),
                               rec['ip'],
                               rec['port'],
                               rec['state'],
                               rec['service'],
                               rec['banner'],
                               rec['version'],
                               rec['domain'],
                               rec['tenant'],
                               rec['tenant_id']
                           )])
        print()

    result, columns = client.execute('SELECT count(ip) FROM nmap GROUP BY ip', with_column_types=True)
    # print(result)


def scan_ip_listed_ports(ip, ports_list):
    command = [
        'sudo',
        'nmap',
        '-p',
        ports_list,
        '-sV',
        ip,
        '-oN',
        './banners_results/ban_' + ip
    ]
    # print(command)
    scan = subprocess.Popen(command)
    scan.wait()


def get_banners(parsed_data):
    for rec in parsed_data:
        ip = None
        port_list = ''
        for sub_rec in rec:
            ip = sub_rec['ip']
            port_list += str(sub_rec['port']) + ','

        port_list = port_list.strip(',')
        print(ip, port_list)
        scan_ip_listed_ports(ip, port_list)


if __name__ == '__main__':
    scan_top50('all_input_ips.txt')
    vulnerable_ips = get_vulnerable_ips('top50_ports_for_all_ips')

    for f_name in os.listdir('vulnerable_ips'):
        scan_vulnerable_ips(f_name)
        print(f_name)
        parsed_data = parse_nmap_result_file('res_' + f_name)
        get_banners(parsed_data)
        load_data_to_ch(parsed_data)
        # print(parsed_data)
