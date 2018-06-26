#!/usr/bin/python3.6
# -*- coding: utf-8 -*-

import re
import sys
import ipaddress
import argparse
import socket
import MySQLdb
from time import localtime, strftime
from pysnmp.hlapi import *


def snmp_walk_2c(community,ip,port,oid):
    raw_answers = []
    mac_table = []
    vlans = []
    fdb_table = {}
    for (errorIndication,
         errorStatus,
         errorIndex,
         varBinds) in nextCmd(SnmpEngine(),
                              CommunityData(community, mpModel=1),
                              UdpTransportTarget((ip, port), timeout=5),
                              ContextData(),
                              ObjectType(ObjectIdentity(oid)),
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
                print(' = '.join([x.prettyPrint() for x in varBind]))


def snmp_get(community,ip,port,oid):
    errorIndication, errorStatus, errorIndex, varBinds = next(
        (getCmd(SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ip, port), timeout=1),
                ContextData(),
                ObjectType(ObjectIdentity(oid)))))
    if errorIndication:
        return 1, errorIndication

    for name, val in varBinds:
        return(val.prettyPrint())


def user_input():
    user_arguments = argparse.ArgumentParser()
    user_arguments.add_argument('-ip', '--ip_address', required=True, nargs=1, help='Введи ip адрес')
    user_arguments.add_argument('-c', '--cummunity', nargs=1, help='Укажи community SNMP')
    user_arguments.add_argument('-p', '--port', nargs=1, help='Укажи порт SNMP на целевом устройстве')
    args = user_arguments.parse_args()

    if len(sys.argv) == 1:
        print('\nНужно указать хотя бы один параметр\n')
        args.print_help()

    if args.ip_address:
        ip_address = args.ip_address[0]
        try:
            ip_address = ipaddress.IPv4Address(ip_address)
            return str(ip_address)
        except ipaddress.AddressValueError as ADDRESS_INPUT_ERROR:
            print('ip address error: ', ADDRESS_INPUT_ERROR)
            sys.exit(1)


def get_if_stat(community,ip,port):
    ports = {}
    raw_answers = []
    tmp_array = []
    for (errorIndication,
         errorStatus,
         errorIndex,
         varBinds) in nextCmd(SnmpEngine(),
                              CommunityData(community, mpModel=1),
                              UdpTransportTarget((ip, port), timeout=2),
                              ContextData(),
                              ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.1')),  # Номер порта IF-MIB::ifIndex.X
                              ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.2')),# Описание (тип) порта IF-MIB::ifDescr.X 1.3.6.1.2.1.2.2.1.2
                              #ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.4')), # MTU порта IF-MIB::ifMTU.X
                              ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.5')), # Скорость порта IF-MIB::ifSpeed.X
                              ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.6')),# Мак адрес порта IF-MIB::ifPhysAddress.X '1.3.6.1.2.1.2.2.1.6'
                              #ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.7')), # Административный статус IF-MIB::ifAdminStatus.X
                              ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.8')),# Оперативный статус IF-MIB::ifOperStatus.X
                              ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.9')),# Последнее ищменение состояния IF-MIB::ifLastChange.X
                              ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.10')),# Входящие октеты IF-MIB::ifInOctets.X
                              #ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.11')), # Входящие ifInUcastPkts IF-MIB::ifInUcastPkts.X
                              # ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.12')), # Входящие НЕ ЮНИКАСТ ifInNUcastPkts IF-MIB::ifInNUcastPkts.X
                              # ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.13')), # Входящие отброшенные ifInDiscards IF-MIB::ifInDiscards.X
                              #ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.14')), # Входящие ошибки IF-MIB::ifInErrors.X
                              # ObjectType(ObjectIdentity('IF-MIB','ifInUnknownProtos')), # Входящие НЕИЗВЕСТНЫЕ IF-MIB::ifInUnknownProtos.X 1.3.6.1.2.1.2.2.1.15
                              ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.16')),# Исходящие октеты IF-MIB::ifOutOctets.X 1.3.6.1.2.1.2.2.1.16
                              # ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.17')), # Исходящие ifOutUcastPkts IF-MIB::ifOutUcastPkts.X
                              # ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.18')), # Исходящие НЕ ЮНИКАСТ ifOutNUcastPkts IF-MIB::ifOutNUcastPkts.X
                              # ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.19')), # Исходящие ifOutDiscards IF-MIB::ifOutDiscards.X
                              #ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.20')), # Исходящие ошибки IF-MIB::outInErrors.X
                              lexicographicMode=False):

        if errorIndication:
            print(errorIndication)

        elif errorStatus:
            print('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
            break
        else:
            raw_answers.append([x.prettyPrint() for x in varBinds])

    length = len(raw_answers[0])
    for answer in raw_answers:
        for i in range(0,length):
            tmp_array.append(answer[i].split(' = ')[1])

    for i in range(0,len(raw_answers)):
        ports[int(tmp_array[0])] = tmp_array[1:length]
        del tmp_array[0:length]

    for key in sorted(ports):
        string = ports[key][2]
        ports[key][2] = string[2:4] + ':' + string[4:6] + ':' + string[6:8] + ':' + string[8:10] + ':' + string[10:12] + ':' + string[12:14]

    return ports


def get_fdb_table(community,ip,port):
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

    raw_answers = []
    mac_table = []
    vlans = []
    fdb_table = {}
    for (errorIndication,
         errorStatus,
         errorIndex,
         varBinds) in nextCmd(SnmpEngine(),
                              CommunityData(community, mpModel=1),
                              UdpTransportTarget((ip, port), timeout=2, retries=5, tagList=''),
                              ContextData(),
                             #ObjectType(ObjectIdentity('1.3.6.1.2.1.17.7.1.4.3.1.1')), # Список VLAN
                             #ObjectType(ObjectIdentity('1.3.6.1.2.1.17.4.3.1')),  # Получаем таблицу соответствий = MAC адрес  = MAC адрес; для DEFAULT VLAN
                              ObjectType(ObjectIdentity('1.3.6.1.2.1.17.7.1.2.1.1.2')), # Здесь список vlan лежит
                              ObjectType(ObjectIdentity('1.3.6.1.2.1.17.7.1.2.2.1.2')),# Таблица FDB по (ВСЕМ - ?) vlan 1.3.6.1.2.1.17.7.1.2 - old
                              #ObjectType(ObjectIdentity('1.3.6.1.2.1.17.2')),
                              # Таблица FDB по (ВСЕМ - ?) vlan 1.3.6.1.2.1.17.7.1.2 - old
                              lexicographicMode=False):

        if errorIndication:
            print(errorIndication)
            break
        elif errorStatus:
            print('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
            break
        else:
            raw_answers.append([' = '.join([x.prettyPrint() for x in varBinds]).split(' = ')[0], ' = '.join([x.prettyPrint() for x in varBinds]).split(' = ')[1]])

    vlan_reg_expression = 'SNMPv2-SMI::mib-2\.17\.7\.1\.2\.1\.1\.2\.'
    for string in raw_answers:
        if re.search(vlan_reg_expression, string[0]):
            vlan_id = string[0].split('SNMPv2-SMI::mib-2.17.7.1.2.1.1.2.')[1]
            vlan_hosts_amount = string[1]
            vlans.append([vlan_id,vlan_hosts_amount])
            continue

    for VLAN_ID in vlans:
        VLAN_ID = VLAN_ID[0]
        mac_reg_expression = re.escape(VLAN_ID) + '\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'
        for string in raw_answers:
            if re.search(mac_reg_expression, string[0]):
                interface = int(string[1])
                mac = re.findall('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$', string[0])[0]
                #mac_original = mac
                mac = __mac_to_hex(mac)
                mac_table.append([mac, interface, VLAN_ID])
                fdb_table[interface] = []
                #print([mac, mac_original, string[1], VLAN_ID])

    for mac_address in mac_table:
        fdb_table[int(mac_address[1])] = fdb_table[int(mac_address[1])] + [[str(mac_address[0]),str(mac_address[2])]]
    return fdb_table, vlans


def get_switch_fdqn(IP_ADDRESS):
    switch_fdqn = socket.gethostbyaddr(IP_ADDRESS)[0]
    return(switch_fdqn)


def get_switch_info(community,ip,port):
    fdb_tables = {}
    statistics_ports = {}

    SWITCH_DESCRIPTION = snmp_get(community,ip,port, '1.3.6.1.2.1.1.1.0')  #1.3.6.1.2.1.1.1 - system descr
    if ( SWITCH_DESCRIPTION[0] == 1 ):
        return 1
    SWITCH_UPTIME_time_tick = snmp_get(community,ip,port, '1.3.6.1.2.1.1.3.0') #1.3.6.1.2.1.1.3 - uptime
    FDB_TABLE, VLANS = get_fdb_table(community,ip,port)
    SWITCH_PORTS = get_if_stat(community,ip,port)


    for vlan in VLANS:
        VLAN_ID = vlan[0]
        VLAN_HOSTS_AMOUNT = vlan[1]
        print('VLAN ID:', VLAN_ID, '\tКоличество хостов во vlan\'e - ', VLAN_HOSTS_AMOUNT)

    for key in sorted(SWITCH_PORTS):
        statistics_ports[int(key)] = SWITCH_PORTS[key]

    for key in sorted(FDB_TABLE):
        fdb_tables[int(key)] = FDB_TABLE[key]

    # Здесь показываем по порядку че отдаем вообще
    print('Статистика портов')
    for key in sorted(statistics_ports):
        print('Порт: ', key, ' ', statistics_ports[key])

    print('FDB таблица')
    for key in sorted(fdb_tables):
        print('Порт: ', key, ' ', fdb_tables[key])


    statistics_switch = [SWITCH_DESCRIPTION, SWITCH_UPTIME_time_tick]
    requests_date = strftime("%Y-%m-%d %H:%M:%S", localtime()) # Время запроса

    return requests_date, statistics_switch, fdb_tables, statistics_ports


def insert_data_db(ip_database, username, password, db_name, sql):
    db = MySQLdb.connect(ip_database, username, password, db_name, charset='utf8')
    cursor = db.cursor()
    cursor.execute(sql)
    db.commit()
    #Закрываем подключение
    db.close()


def get_data_db(ip_database, username, password, db_name, sql):
    db = MySQLdb.connect(ip_database, username, password, db_name, charset='utf8')
    cursor = db.cursor()
    cursor.execute(sql)
    raw_data = cursor.fetchone()
    db.close()
    return raw_data[0]


def write_statistics_ports(community, ip, port, db_ip_address = '10.4.5.54' , db_username = 'pysnmp',  db_password = '123456', db_name = 'switch_snmp'):

    ports = get_if_stat(community,ip,port)
    requests_date = strftime("%Y-%m-%d %H:%M:%S", localtime())  # Время запроса

    sql_insert_datetime = """ INSERT requests(DATE) values('%(date_time)s')""" % {"date_time": requests_date}
    insert_data_db(db_ip_address, db_username, db_password, db_name, sql_insert_datetime)

    sql_get_id_request = """ SELECT id_requests FROM requests where DATE = '%(date_time)s' """ % {
        "date_time": requests_date}
    id_request = get_data_db(db_ip_address, db_username, db_password, db_name, sql_get_id_request)

    sql_get_sw_id = """SELECT id_switches FROM switches where switches.ip = '%(ip_address)s'""" % {
        "ip_address": IP_ADDRESS}
    id_switch = get_data_db(db_ip_address, db_username, db_password, db_name, sql_get_sw_id)

    for port_number in sorted(ports):
        sql_get_ports_id_port = """ SELECT id_ports from switch_snmp.ports inner join switches using(id_switches) 
                    where port_number = '%(port_number)s' and id_switches = '%(id_switch)s'; """ % {
                    "port_number": port_number, "id_switch": id_switch}
        id_ports = get_data_db(db_ip_address, db_username, db_password, db_name, sql_get_ports_id_port)

        sql_insert_statistics_ports = """ INSERT statistics_ports(id_ports, port_description, port_speed, 
                    port_mac, port_status, port_uptime, port_in_octets, port_out_octets, id_requests) values 
                    ('%(id_ports)s', '%(port_description)s', '%(port_speed)s', '%(port_mac)s', '%(port_status)s', 
                    '%(port_uptime)s', '%(port_in_octets)s', '%(port_out_octets)s', '%(id_requests)s') """ \
                                      % {"id_ports": id_ports, "port_description": ports[port_number][0],
                                         "port_speed": ports[port_number][1],
                                         "port_mac": ports[port_number][2], "port_status": ports[port_number][3],
                                         "port_uptime": ports[port_number][4], "port_in_octets": ports[port_number][5],
                                         "port_out_octets": ports[port_number][6], "id_requests": id_request}
        insert_data_db(db_ip_address, db_username, db_password, db_name, sql_insert_statistics_ports)


def write_fdb_table(community, ip, port, db_ip_address = '10.4.5.54' , db_username = 'pysnmp',  db_password = '123456', db_name = 'switch_snmp'):
    fdb_tables, vlans = get_fdb_table(community, ip, port)
    requests_date = strftime("%Y-%m-%d %H:%M:%S", localtime())  # Время запроса

    sql_get_sw_id = """SELECT id_switches FROM switches where switches.ip = '%(ip_address)s'""" % {
        "ip_address": IP_ADDRESS}
    id_switch = get_data_db(db_ip_address, db_username, db_password, db_name, sql_get_sw_id)


    sql_insert_datetime = """ INSERT requests(DATE) values('%(date_time)s')""" % {"date_time": requests_date}
    insert_data_db(db_ip_address, db_username, db_password, db_name, sql_insert_datetime)

    sql_get_id_request = """ SELECT id_requests FROM requests where DATE = '%(date_time)s' """ % {
        "date_time": requests_date}
    id_requests = get_data_db(db_ip_address, db_username, db_password, db_name, sql_get_id_request)

    for port_number in sorted(fdb_tables):
        sql_get_ports_id_port = """ SELECT id_ports from ports inner join switches using(id_switches) 
                            where port_number = '%(port_number)s' and id_switches = '%(id_switch)s'; """ % {
            "port_number": port_number, "id_switch": id_switch}
        try:
            id_ports = get_data_db(db_ip_address, db_username, db_password, db_name, sql_get_ports_id_port)
        except TypeError as error_type:
            print('ERROR: ', error_type, ' Port number: ', port_number, ' ', SWITCH_FDQN)
            continue
        for mac_string in fdb_tables[port_number]:
            mac_address = mac_string[0]
            mac_vid = mac_string[1]
            sql_insert_fdb_table = """ INSERT FDB_tables(id_requests, id_ports,  mac_address, VID)
                values('%(id_requests)s', '%(id_ports)s', '%(mac_address)s', '%(VID)s')""" % \
                                   {"id_requests": id_requests, "id_ports": id_ports, "mac_address": mac_address,
                                    "VID": mac_vid}
            insert_data_db(db_ip_address, db_username, db_password, db_name, sql_insert_fdb_table)


def write_switch_full_data(community, ip, port, requests_date='', db_ip_address = '10.4.5.54' , db_username = 'pysnmp',  db_password = '123456', db_name = 'switch_snmp'):
    # Записываем временную метку в БД
    if len(requests_date) == 0:
        requests_date = strftime("%Y-%m-%d %H:%M:%S", localtime())  # Время запроса

    sql_insert_datetime = """ INSERT requests(DATE) values('%(date_time)s')""" % {"date_time": requests_date}
    insert_data_db(db_ip_address, db_username, db_password, db_name, sql_insert_datetime)
    #

    # Запросы id  временной метки и id свитча
    sql_get_id_request = """ SELECT id_requests FROM requests where DATE = '%(date_time)s' """ % {
        "date_time": requests_date}
    sql_get_sw_id = """SELECT id_switches FROM switches where switches.ip = '%(ip_address)s'""" % {
        "ip_address": ip}
    id_switch = get_data_db(db_ip_address, db_username, db_password, db_name, sql_get_sw_id)
    id_request = get_data_db(db_ip_address, db_username, db_password, db_name, sql_get_id_request)
    #

    # Получаем статистику портов
    ports = get_if_stat(community, ip, port)
    # Получаем fdb таблицу и информацию о vlan
    fdb_tables, vlans = get_fdb_table(community, ip, port)
    # Получаем switch Description
    switch_description = snmp_get(community, ip, port, '1.3.6.1.2.1.1.1.0')  # 1.3.6.1.2.1.1.1 - system descr
    # Получаем switch uptime
    switch_uptime = snmp_get(community, ip, port, '1.3.6.1.2.1.1.3.0')  # 1.3.6.1.2.1.1.3 - uptime

    for port_number in sorted(ports):
        sql_get_ports_id_port = """ SELECT id_ports from switch_snmp.ports inner join switches using(id_switches) 
                    where port_number = '%(port_number)s' and id_switches = '%(id_switch)s'; """ % {
                    "port_number": port_number, "id_switch": id_switch}
        id_ports = get_data_db(db_ip_address, db_username, db_password, db_name, sql_get_ports_id_port)

        sql_insert_statistics_ports = """ INSERT statistics_ports(id_ports, port_description, port_speed, 
                    port_mac, port_status, port_uptime, port_in_octets, port_out_octets, id_requests) values 
                    ('%(id_ports)s', '%(port_description)s', '%(port_speed)s', '%(port_mac)s', '%(port_status)s', 
                    '%(port_uptime)s', '%(port_in_octets)s', '%(port_out_octets)s', '%(id_requests)s') """ \
                                      % {"id_ports": id_ports, "port_description": ports[port_number][0],
                                         "port_speed": ports[port_number][1],
                                         "port_mac": ports[port_number][2], "port_status": ports[port_number][3],
                                         "port_uptime": ports[port_number][4], "port_in_octets": ports[port_number][5],
                                         "port_out_octets": ports[port_number][6], "id_requests": id_request}
        insert_data_db(db_ip_address, db_username, db_password, db_name, sql_insert_statistics_ports)

    for port_number in sorted(fdb_tables):
        sql_get_ports_id_port = """ SELECT id_ports from ports inner join switches using(id_switches) 
                            where port_number = '%(port_number)s' and id_switches = '%(id_switch)s'; """ % {
            "port_number": port_number, "id_switch": id_switch}
        try:
            id_ports = get_data_db(db_ip_address, db_username, db_password, db_name, sql_get_ports_id_port)
        except TypeError as error_type:
            print('ERROR: ', error_type, ' Port number: ', port_number, ' ', SWITCH_FDQN)
            continue
        for mac_string in fdb_tables[port_number]:
            mac_address = mac_string[0]
            mac_vid = mac_string[1]
            sql_insert_fdb_table = """ INSERT FDB_tables(id_requests, id_ports,  mac_address, VID)
                values('%(id_requests)s', '%(id_ports)s', '%(mac_address)s', '%(VID)s')""" % \
                                   {"id_requests": id_request, "id_ports": id_ports, "mac_address": mac_address,
                                    "VID": mac_vid}
            insert_data_db(db_ip_address, db_username, db_password, db_name, sql_insert_fdb_table)

    sql_insert_into_statistis_switch = """ INSERT statistics_switch(id_switches, id_requests, switch_description, switch_uptime) 
        values('%(id_switches)s', '%(id_requests)s', '%(switch_description)s', '%(switch_uptime)s')""" % {
                                                "id_switches": id_switch, "id_requests": id_request,
                                                "switch_description": switch_description, "switch_uptime": switch_uptime }

    insert_data_db(db_ip_address, db_username, db_password, db_name, sql_insert_into_statistis_switch)
    sql_get_id_vlan_from_statistics_switch = """ SELECT id_vlan FROM statistics_switch inner join requests using(id_requests) where id_requests = '%(id_request)s' """ % {"id_request": id_request}
    id_vlan = get_data_db(db_ip_address, db_username, db_password, db_name, sql_get_id_vlan_from_statistics_switch)

    for vlan in vlans:
        sql_insert_into_vlan_table = """ INSERT vlan_table(id_vlan, VID, host_amount) values('%(id_vlan)s', '%(VID)s', '%(host_amount)s' ) """ %\
                                     { "id_vlan": id_vlan, "VID": vlan[0], "host_amount": vlan[1]}
        insert_data_db(db_ip_address, db_username, db_password, db_name, sql_insert_into_vlan_table)


if __name__ == "__main__":
    DB_IP_ADDRESS = '10.4.5.54'
    DB_USERNAME = 'pysnmp'
    DB_PASSWORD = '123456'
    DB_NAME = 'switch_snmp'

    COMMUNITY='public'
    SNMP_PORT='161'
    SWITCH_WORKSHOP = ['10.4.0.200', '10.4.0.201', '10.4.0.202', '10.4.0.203',
                       '10.4.0.204', '10.4.0.205', '10.4.0.206', '10.4.0.207', '10.4.0.208',
                       '10.4.0.209', '10.4.0.210', '10.4.0.211', '10.4.0.212', '10.4.0.213',
                       '10.4.0.214', '10.4.0.215', '10.4.0.217', '10.4.0.218']
    #TEST = ['10.4.0.213', '10.4.0.214', '10.4.0.215', '10.4.0.217', '10.4.0.218']
    IP_ADDRESS_LIST = SWITCH_WORKSHOP
    if len(IP_ADDRESS_LIST) != 0:
        time_start = strftime("%H:%M:%S", localtime())
        REQUEST_DATE = strftime("%Y-%m-%d %H:%M:%S", localtime())  # Время запроса
        for IP_ADDRESS in IP_ADDRESS_LIST:
            SWITCH_FDQN = get_switch_fdqn(IP_ADDRESS)
            write_switch_full_data(COMMUNITY, IP_ADDRESS, SNMP_PORT, REQUEST_DATE)

        time_finish = strftime("%H:%M:%S", localtime())
        print('\n' ,time_start, time_finish)

    else:
        IP_ADDRESS=user_input()
        write_statistics_ports(COMMUNITY, IP_ADDRESS, SNMP_PORT)