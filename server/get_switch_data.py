#!/usr/bin/python3.6
# -*- coding: utf-8 -*-

import re
#import sys
#import ipaddress
#import argparse
import socket
#import MySQLdb
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

            interfaces[if_number] = {
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

    return switches

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
    switches = ['10.1.13.249', '10.1.13.252']
    start1 = time.time()
    switch_raw = get_switch_data(agent['community'], switches, agent['snmp_port'])
    end1 = time.time()
    start2 = time.time()
    switches = parse_switch_data(switch_raw)

    for switch in switches:
        for key in sorted(switch):
            print(key, switch[key])

    end2 = time.time()
    print('\n', end1 - start1 , end2 - start2, end2 - start1)