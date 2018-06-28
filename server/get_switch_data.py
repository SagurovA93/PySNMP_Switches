#!/usr/bin/python3.6
# -*- coding: utf-8 -*-

import re
import sys
import ipaddress
import argparse
import socket
import MySQLdb
import time
from pysnmp.hlapi import *


def snmp_walk_2c(community,ip,port,oid):
    raw_answer = []
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
                raw_answer.append(' = '.join([x.prettyPrint() for x in varBind]))
    return raw_answer


def get_switch_data(community, switch_list, port):

    switches = []
    switch = {}

    for ip in switch_list:
        raw_interfaces = []
        raw_fdb = []
        raw_arp = []
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

        raw_vlan_list = snmp_walk_2c(community, ip, port, '1.3.6.1.2.1.17.7.1.2.1.1.2')
        raw_fdb = snmp_walk_2c(community, ip, port, '1.3.6.1.2.1.17.7.1.2.2.1.2')
        raw_arp = snmp_walk_2c(community, ip, port, ('IP-MIB', 'ipNetToMediaPhysAddress')) #!

        switch = {
            'ip address': ip,
            'raw interfaces': raw_interfaces,
            'raw vlan list': raw_vlan_list,
            'raw fdb': raw_fdb,
            'raw arp': raw_arp
        }
        switches.append(switch)

    return switches


def parse_switch_data(switch_data):
    switches = []
    for switch in switch_data:
        switch_ip = switch['ip address']

        switch_info = {
            'ip address': switch_ip,
        }
        interfaces = {}
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

            interfaces[if_number] = {
                'interface description': if_descr,
                'interface speed': if_speed,
                'interface mac': if_mac,
                'interface status': if_state,
                'interface uptime': if_uptime,
                'interface in Bytes': if_inB,
                'interface out Bytes': if_outB
                }
        switch_info["interfaces"] = interfaces

        raw_fdb = switch['raw fdb']
        for fdb_table in raw_fdb:
            print(fdb_table)



if __name__ == "__main__":
    agent = {
        'community': 'public',
        'ip_address': '10.4.0.213',
        'snmp_port': '161'
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

    SWITCHES_IZ2 = SWITCH_WORKSHOP + SWITCH_ABK
    switches = ['10.4.0.200']
    start1 = time.time()
    switch_raw = get_switch_data(agent['community'], switches, agent['snmp_port'])
    end1 = time.time()
    print(end1 - start1)
    parse_switch_data(switch_raw)