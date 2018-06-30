#!/usr/bin/python3.6
# -*- coding: utf-8 -*-

import re
import pymysql
import socket
from time import localtime, strftime
import time
import datetime
from pysnmp.hlapi import *


def snmp_walk_2c(community, ip, port, oid ):
    raw_answer = []
    object_type = ObjectType(ObjectIdentity(oid))
    for (errorIndication,
         errorStatus,
         errorIndex,
         varBinds) in nextCmd(SnmpEngine(),
                              CommunityData(community, mpModel=1),
                              UdpTransportTarget((ip, port), timeout=1),
                              ContextData(),
                              object_type,
                              lexicographicMode=False):

        if errorIndication:
            print(errorIndication)
            break
        elif errorStatus:
            print('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
            break
        else:
            for varBind in varBinds:
                raw_answer.append(' = '.join([x.prettyPrint() for x in varBind]))
    return raw_answer


def get_switch_data(community, switch_list, port):

    switches = []

    for ip in switch_list:

        raw_interfaces = []

        for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(SnmpEngine(),
                              CommunityData(community, mpModel=1),
                              UdpTransportTarget((ip, port), timeout=2),
                              ContextData(),
                              # Статистика интерфейсов
                              ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.1')),  # Номер порта IF-MIB::ifIndex.X
                              ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.2')),
                              ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.5')),  # Скорость порта IF-MIB::ifSpeed.X
                              ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.6')),# Мак адрес порта IF-MIB::ifPhysAddress.X '1.3.6.1.2.1.2.2.1.6'
                              ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.8')),# Оперативный статус IF-MIB::ifOperStatus.X
                              ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.9')),# Последнее ищменение состояния IF-MIB::ifLastChange.X
                              ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.10')),# Входящие октеты IF-MIB::ifInOctets.X
                              ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.16')),
                              lexicographicMode=False):

            if errorIndication:
                print(errorIndication)

            elif errorStatus:
                print('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
                break
            else:
                raw_interfaces.append([x.prettyPrint() for x in varBinds])

        raw_description = snmp_walk_2c(community, ip, port, '1.3.6.1.2.1.1.1')
        raw_switch_uptime = snmp_walk_2c(community, ip, port, '1.3.6.1.2.1.1.3') #1.3.6.1.2.1.1.3
        raw_vlan_list = snmp_walk_2c(community, ip, port, '1.3.6.1.2.1.17.7.1.2.1.1.2')
        raw_fdb = snmp_walk_2c(community, ip, port, '1.3.6.1.2.1.17.7.1.2.2.1.2')
        raw_arp = snmp_walk_2c(community, ip, port, '1.3.6.1.2.1.4.22.1.2') #! IP-MIB.ipNetToMediaPhysAddress
        #1.3.6.1.4.1.171.11.55.2.2.1.4.3    - Загрузка CPU за пять минут на DGS-3312SR
        #1.3.6.1.4.1.171.12.1.1.6.3         - Загрузка CPU за пять минут на DGS-3420-52T
        switch = {
            'ip address': ip,
            'raw description': raw_description,
            'raw switch uptime': raw_switch_uptime,
            'raw interfaces': raw_interfaces,
            'raw vlan list': raw_vlan_list,
            'raw fdb': raw_fdb,
            'raw arp': raw_arp
        }
        switches.append(switch)

    return switches


def get_switch_table_db(db_address, user, password, db_name, charset):
    # SQL - запросы чтение
    get_switches = "SELECT * FROM switches"
    get_ports = "SELECT * FROM ports"

    # Подключиться к базе данных.
    connection = pymysql.connect(host=db_address,
                                 user=user,
                                 password=password,
                                 db=db_name,
                                 charset=charset,
                                 cursorclass=pymysql.cursors.DictCursor)
    try:

        with connection.cursor() as cursor:
            # 1. Взять всю таблицу свитчей
            cursor.execute(get_switches)
            switches_table = cursor.fetchall()
            # 2. Взять все порты свитчей
            cursor.execute(get_ports)
            ports_table = cursor.fetchall()

    finally:
        connection.close()

    return switches_table, ports_table


def parse_switch_data(switch_data):

    def __mac_to_hex(mac_address):
        number_letter = {15: 'F', 14: 'E', 13: 'D', 12: 'C', 11: 'B', 10: 'A'}
        def number_to_letter(R):
            if R < 10:
                R = str(R)
                return R
            for key in number_letter:
                if R == key:
                    R = number_letter.get(key)
                    return R

        mac_address_hex = ''
        mac_address = mac_address.split('.')
        i = 0
        for octet in mac_address:
            i = i + 1
            Result = ''
            N = int(octet)
            if N < 16:
                N = number_to_letter(N)
                Result = '0' + N
            else:
                while N >= 16:
                    R = N // 16
                    N = N - (R * 16)
                    R = number_to_letter(R)
                    Result = str(Result) + str(R)
                N = number_to_letter(N)
                Result = str(Result) + str(N)

            if i != 6:
                mac_address_hex = mac_address_hex + Result + ':'
            else:
                mac_address_hex = mac_address_hex + Result

        return (mac_address_hex)
    def __get_hostname(host_ip):
        try:
            hostname = socket.gethostbyaddr(host_ip)[0]
        except:
            hostname = 'Unknown'
        return hostname

    switches = []
    for switch in switch_data:
        switch_ip = switch['ip address']

        interfaces = {}
        vlans = {}
        arp_table = {}
        fdb_table = {}
        raw_interfaces = switch['raw interfaces']
        for interface in raw_interfaces:

            if_number = interface[0].split(' = ')[1]
            if_descr = interface[1].split(' = ')[1]
            if_speed = interface[2].split(' = ')[1]
            if_mac = interface[3].split(' = ')[1].upper()
            if_mac = if_mac[2:4] + ':' + if_mac[4:6] + ':' + if_mac[6:8] + ':' \
                     + if_mac[8:10] + ':' + if_mac[10:12] + ':' + if_mac[12:14]
            if_state = interface[4].split(' = ')[1]
            if_uptime = interface[5].split(' = ')[1]
            if_inB = interface[6].split(' = ')[1]
            if_outB = interface[7].split(' = ')[1]

            interfaces[int(if_number)] = {
                'interface description': if_descr,
                'interface speed': if_speed,
                'interface mac': if_mac,
                'interface status': if_state,
                'interface uptime': if_uptime,
                'interface in Bytes': if_inB,
                'interface out Bytes': if_outB
                }

        raw_vlan = switch['raw vlan list']
        for vlan_string in raw_vlan:
            vid, hosts_amount = vlan_string.split(' = ')
            vid = vid.split('SNMPv2-SMI::mib-2.17.7.1.2.1.1.2.')[1]
            vlans[vid] = {
                'host amount': hosts_amount
            }

        raw_arp = switch['raw arp']
        for arp_string in raw_arp:
            host_ip, host_mac = arp_string.split(' = ')
            host_ip = re.findall('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host_ip)[0]
            host_mac = host_mac[2:4] + ':' + host_mac[4:6] + ':' + host_mac[6:8] + ':' \
                       + host_mac[8:10] + ':' + host_mac[10:12] + ':' + host_mac[12:14]
            if host_mac != 'ff:ff:ff:ff:ff:ff':
                arp_table[host_mac.upper()] = {
                    'host ip': host_ip
                }

        raw_fdb = switch['raw fdb']
        for fdb_string in raw_fdb:
            mac, port = fdb_string.split(' = ')
            mac = re.findall('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$', mac)[0].upper()
            mac = __mac_to_hex(mac)
            try:
                host_ip = arp_table[mac].get('host ip')
                hostname = 'Unknown'
                #hostname = __get_hostname(host_ip)
            except KeyError:
                host_ip = 'Unknown'
                hostname = 'Unknown'
            fdb_table[port] = {
                'host mac': mac,
                'host ip': host_ip,
                'host name': hostname
            }

        raw_description = switch['raw description']
        raw_switch_uptime = switch['raw switch uptime']
        switch_description = raw_description[0].split(' = ')[1]
        switch_uptime = datetime.timedelta(seconds=(int(raw_switch_uptime[0].split(' = ')[1]) / 100))

        switch_info = {
            'ip address': switch_ip,
            'switch description': switch_description,
            'switch uptime': switch_uptime,
            'interfaces': interfaces,
            'vlans': vlans,
            'fdb table': fdb_table,
        }

        switches.append(switch_info)

    # Добавляю актуальную информацию по свитчам и портам из БД
    # switch_id & ip_ports
    switches_table, ports_table = get_switch_table_db(cred['host'], cred['user'], cred['passwd'], cred['db'], cred['charset'])

    for switch in switches:
        switch_ip = switch['ip address']
        switch_if = switch['interfaces']

        for switch_tb in switches_table: # Получаю id switch для каждого свитча
            if switch_tb['ip'] == switch_ip:
                id_switches = switch_tb['id_switches']
                switch['switch id'] = id_switches # Добавляю id свитча в словарь свитча

        switch_ports = []  # Выбираю только порты данного свитча из общей солянки
        for port in ports_table:
            if port['id_switches'] == switch['switch id']:
                switch_ports.append(port)

        for port in switch_ports:
            id_ports, port_number = port['id_ports'], port['port_number'] # id и номер порта  конкретного свитча
            try:
                switch_if[int(port_number)]['port id'] = id_ports   # Добавляю ключ 'port id' во временный словарь для интерфейсов свитча
            except KeyError:
                print('У свитча нет такого порта, который есть в базе:',  '\n',
                      'Свитч:', switch_ip, '\n'
                      'Номер порта: ', int(port_number), '\n',
                      'id порта в базе:', id_ports, '\n',
                      )
                continue
            except:
                print('Произошла непредвиденная ошибка, при обработке портов из базы')
        switch['interfaces'] = switch_if

    return switches


if __name__ == "__main__":

    snmp_agent = {
        'community': 'public',
        'port': 161,
    }

    cred = {
        'host': '10.4.5.54',
        'user': 'pysnmp',
        'passwd': '123456',
        'db': 'switch_snmp',
        'charset': 'utf8',
    }

    SWITCH_WORKSHOP = ['10.4.0.200', '10.4.0.201', '10.4.0.202', '10.4.0.203',
                       '10.4.0.204', '10.4.0.205', '10.4.0.206', '10.4.0.207', '10.4.0.208',
                       '10.4.0.209', '10.4.0.210', '10.4.0.211', '10.4.0.212', '10.4.0.213',
                       '10.4.0.214', '10.4.0.215', '10.4.0.217', '10.4.0.218']

    SWITCH_ABK = ['10.4.0.1', '10.4.100.12', '10.4.100.13', '10.4.100.111',
                  '10.4.100.121', '10.4.100.131', '10.4.100.171', '10.4.100.211',
                  '10.4.100.212', '10.4.100.213', '10.4.100.214', '10.4.100.215',
                  '10.4.100.216', '10.4.100.231', '10.4.100.251']

    N16_SWITCHES = ['10.1.13.249', '10.1.13.252']

    SWITCHES_IZ2 = SWITCH_WORKSHOP + SWITCH_ABK

    start1 = time.time()
    switch_raw = get_switch_data(snmp_agent['community'], ['10.1.13.249'], snmp_agent['port'])
    end1 = time.time()

    start2 = time.time()
    switches = parse_switch_data(switch_raw)
    end2 = time.time()

    start3 = time.time()
    for switch in switches:
        for key in switch:
            print(key, switch[key])
    end3 = time.time()

    print('\n',
          'Сбор данных: ', round(end1 - start1, 5), 'секунд', '\n',
          'Парсинг данных: ', round(end2 - start2, 5), 'секунд', '\n',
          'Запись в БД:', round(end3 - start3, 5), 'секунд', '\n',
          'Общее время: ', round(end3 - start1, 3), 'секунд', '\n',
          )