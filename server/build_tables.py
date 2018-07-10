#!/usr/bin/python3.6
# -*- coding: utf-8 -*-

import sys
import socket
import pymysql
from pysnmp.hlapi import *

def get_switch_ports(community,ip,port):
    ports = []
    raw_answers = []
    error_status = False
    for (errorIndication,
         errorStatus,
         errorIndex,
         varBinds) in nextCmd(SnmpEngine(),
                              CommunityData(community, mpModel=1),
                              UdpTransportTarget((ip, port), timeout=2),
                              ContextData(),
                              ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.1')),  # Номер порта IF-MIB::ifIndex.X
                              lexicographicMode=False):

        if errorIndication:
            print(errorIndication)
            error_status = True
            break

        elif errorStatus:
            print('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
            error_status = True
            break
        else:
            raw_answers.append([x.prettyPrint() for x in varBinds])

    try:
        length = len(raw_answers[0])
    except IndexError:
        return ports, error_status

    for answer in raw_answers:
        for i in range(0,length):
            ports.append(answer[i].split(' = ')[1])

    return ports, error_status


def insert_data_db(ip_database, username, password, db_name, sql):
    db = pymysql.connect(ip_database, username, password, db_name, charset='utf8')
    cursor = db.cursor()
    try:
        cursor.execute(sql)
        db.commit()
    except pymysql.err.IntegrityError as err_mysql_integr:
        print('Ошибка при добавлении свитча', err_mysql_integr)
    #Закрываем подключение
    db.close()


def get_data_db(ip_database, username, password, db_name, sql):
    db = pymysql.connect(ip_database, username, password, db_name, charset='utf8')
    cursor = db.cursor()
    cursor.execute(sql)
    raw_data = cursor.fetchone()
    db.close()
    return raw_data[0]


if __name__ == "__main__":

    cred = {
        'host': '10.4.5.54',
        'user': 'pysnmp',
        'passwd': '123456',
        'db': 'switch_snmp_lldp_t1',
        'charset': 'utf8',
    }

    COMMUNITY = 'public'
    SNMP_PORT = '161'
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

    TEST = ['10.4.0.201']
    IP_ADDRESS_LIST = SWITCHES_IZ2

    for IP_ADDRESS in IP_ADDRESS_LIST:
        try:
            SWITCH_FDQN = socket.gethostbyaddr(IP_ADDRESS)[0]
        except socket.herror: # Если невозможно разрешить FDQN указанного адреса - SWITCH_FDQN = IP_ADDRESS
            SWITCH_FDQN = IP_ADDRESS

        print(SWITCH_FDQN)

        SWITCH_PORTS, error_status = get_switch_ports(COMMUNITY,IP_ADDRESS,SNMP_PORT)

        if error_status:
            continue
        else:
            SQL_INSERT_SW = """INSERT INTO switches(ip, FDQN) values ('%(ip_address)s', '%(switch_fdqn)s')""" % {
                "ip_address": IP_ADDRESS, "switch_fdqn": SWITCH_FDQN}
            insert_data_db(cred['host'], cred['user'], cred['passwd'], cred['db'], SQL_INSERT_SW)

            SQL_GET_SW_ID = """SELECT id_switches FROM switches where switches.ip = '%(ip_address)s'""" % {
                "ip_address": IP_ADDRESS}
            ID_SWITCH = get_data_db(cred['host'], cred['user'], cred['passwd'], cred['db'], SQL_GET_SW_ID)

            for port in SWITCH_PORTS:
                PORT_NUMBER = port
                SQL_INSERT_PORT = """INSERT INTO ports(port_number, id_switches) values ('%(port_number)s', '%(id_switches)s')""" % {
                    "port_number": PORT_NUMBER, "id_switches": ID_SWITCH}
                insert_data_db(cred['host'], cred['user'], cred['passwd'], cred['db'], SQL_INSERT_PORT)