#!/usr/bin/python3.6
# -*- coding: utf-8 -*-

import re
from pysnmp.hlapi import *

def snmp_walk_2c(community,ip,port,oid):
    for (errorIndication,
         errorStatus,
         errorIndex,
         varBinds) in nextCmd(SnmpEngine(),
                              CommunityData(community, mpModel=1),
                              UdpTransportTarget((ip, port)),
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


def snmp_get(community,ip,port,oid_1,oid_2,oid_3):
    errorIndication, errorStatus, errorIndex, varBinds = next(
        (getCmd(SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ip, port)),
                ContextData(),
                ObjectType(ObjectIdentity(oid_1, oid_2, oid_3)))))
    for name, val in varBinds:
        return(val.prettyPrint())


def mac_to_hex(mac_address):
    def number_to_letter(R):
        if R == 15:
            R = 'F'
        elif R == 14:
            R = 'E'
        elif R == 13:
            R = 'D'
        elif R == 12:
            R = 'C'
        elif R == 11:
            R = 'B'
        elif R == 10:
            R = 'A'
        else:
            R = str(R)
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

    return(mac_address_hex)


def get_fdb_table(community,ip,port):
    raw_answers = []
    mac_table = []
    vlans = []
    fdb_table = {}
    for (errorIndication,
         errorStatus,
         errorIndex,
         varBinds) in nextCmd(SnmpEngine(),
                              CommunityData(community, mpModel=1),
                              UdpTransportTarget((ip, port), timeout=15),
                              ContextData(),
                             #ObjectType(ObjectIdentity('1.3.6.1.2.1.17.7.1.4.3.1.1')), # Список VLAN
                             #ObjectType(ObjectIdentity('1.3.6.1.2.1.17.4.3.1')),  # Получаем таблицу соответствий = MAC адрес  = MAC адрес; для DEFAULT VLAN
                              ObjectType(ObjectIdentity('1.3.6.1.2.1.17.7.1.2.1.1.2')),
                              ObjectType(ObjectIdentity('1.3.6.1.2.1.17.7.1.2.2.1.2')), # Таблица FDB по (ВСЕМ - ?) vlan 1.3.6.1.2.1.17.7.1.2 - old
                              #
                              lexicographicMode=False):

        if errorIndication:
            print(errorIndication)
            break
        elif errorStatus:
            print('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
            break
        else:
            print([' = '.join([x.prettyPrint() for x in varBinds]).split(' = ')[0], ' = '.join([x.prettyPrint() for x in varBinds]).split(' = ')[1]])
            raw_answers.append([' = '.join([x.prettyPrint() for x in varBinds]).split(' = ')[0], ' = '.join([x.prettyPrint() for x in varBinds]).split(' = ')[1]])

    for string in raw_answers:
        vlan_reg_expression = re.compile('SNMPv2-SMI::mib-2.17.7.1.2')
        vlan = vlan_reg_expression.search(string[0])
        if vlan:
            vlan_id = string[0].split('SNMPv2-SMI::mib-2.17.7.1.2.')[1]
            vlan_hosts_amount = string[1]
            vlans.append([vlan_id,vlan_hosts_amount])
            continue

    #for VLAN_ID in vlans:
    #    VLAN_ID = VLAN_ID[0]
    #    mac_reg_expression = re.escape(VLAN_ID) + '\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'
    #    for string in raw_answers:
    #        if re.search(mac_reg_expression, string[0]):
    #            interface = string[1]
    #            mac = re.findall('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$', string[0])[0]
    #            mac_original = mac
    #            mac = mac_to_hex(mac)
    #            mac_table.append([mac, interface, VLAN_ID])
    #            fdb_table[interface] = []
                #print([mac, mac_original, string[1], VLAN_ID])

    #for string in mac_table:
    #    port_number = str(string[1])
    #    fdb_table[port_number] = fdb_table.get(port_number) + [[str(string[0]),str(string[2])]]
    print(vlans)
    return fdb_table, vlans


if __name__ == "__main__":
    IP_ADDRESS='10.4.0.1'
    COMMUNITY='public'
    PORT='161'

    FDB_TABLE,VLANS = get_fdb_table(COMMUNITY,IP_ADDRESS,PORT)
    #for vlan in VLANS:
    #    VLAN_ID = vlan[0]
    #    VLAN_HOSTS_AMOUNT = vlan[1]
    #    print('VLAN ID:', VLAN_ID, '\tКоличество хостов во vlan\'e - ', VLAN_HOSTS_AMOUNT)

    #print('FDB таблица')
    #for key in FDB_TABLE:
    #    print('Порт: ',key,' ',FDB_TABLE[key])

