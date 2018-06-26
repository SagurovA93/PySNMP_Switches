#!/usr/bin/python3.6
# -*- coding: utf-8 -*-

import sys
import socket
import MySQLdb
from pysnmp.hlapi import *

def get_switch_ports(community,ip,port):
    ports = []
    raw_answers = []
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
            sys.exit(1)

        elif errorStatus:
            print('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
            break
        else:
            raw_answers.append([x.prettyPrint() for x in varBinds])

    length = len(raw_answers[0])
    for answer in raw_answers:
        for i in range(0,length):
            ports.append(answer[i].split(' = ')[1])

    return ports


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


if __name__ == "__main__":
    DB_IP_ADDRESS = '10.4.5.54'
    DB_USERNAME = 'pysnmp'
    DB_PASSWORD = '123456'
    DB_NAME = 'switch_snmp'

    COMMUNITY = 'public'
    SNMP_PORT = '161'
    SWITCH_WORKSHOP = ['10.4.0.200', '10.4.0.201', '10.4.0.202', '10.4.0.203',
                       '10.4.0.204', '10.4.0.205', '10.4.0.206', '10.4.0.207', '10.4.0.208',
                       '10.4.0.209', '10.4.0.210', '10.4.0.211', '10.4.0.212', '10.4.0.213',
                       '10.4.0.214', '10.4.0.215', '10.4.0.217', '10.4.0.218']
    TEST = ['10.4.0.201']
    IP_ADDRESS_LIST = SWITCH_WORKSHOP

    for IP_ADDRESS in IP_ADDRESS_LIST:
        SWITCH_FDQN = socket.gethostbyaddr(IP_ADDRESS)[0]
        print(SWITCH_FDQN)
        SWITCH_PORTS = get_switch_ports(COMMUNITY,IP_ADDRESS,SNMP_PORT)
        SQL_INSERT_SW = """INSERT INTO switches(ip, FDQN) values ('%(ip_address)s', '%(switch_fdqn)s')""" % {
            "ip_address": IP_ADDRESS, "switch_fdqn": SWITCH_FDQN}
        insert_data_db(DB_IP_ADDRESS, DB_USERNAME, DB_PASSWORD, DB_NAME, SQL_INSERT_SW)

        SQL_GET_SW_ID = """SELECT id_switches FROM switches where switches.ip = '%(ip_address)s'""" % {
            "ip_address": IP_ADDRESS}
        ID_SWITCH = get_data_db(DB_IP_ADDRESS, DB_USERNAME, DB_PASSWORD, DB_NAME, SQL_GET_SW_ID)

        for port in SWITCH_PORTS:
            PORT_NUMBER = port
            SQL_INSERT_PORT = """INSERT INTO ports(port_number, id_switches) values ('%(port_number)s', '%(id_switches)s')""" % {
                "port_number": PORT_NUMBER, "id_switches": ID_SWITCH}
            insert_data_db(DB_IP_ADDRESS, DB_USERNAME, DB_PASSWORD, DB_NAME, SQL_INSERT_PORT)