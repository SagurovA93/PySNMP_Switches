#!/usr/bin/python3.6
# -*- coding: utf-8 -*-

import re
import sys
import ipaddress
import argparse
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
                UdpTransportTarget((ip, port)),
                ContextData(),
                ObjectType(ObjectIdentity(oid)))))
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
            print(ADDRESS_INPUT_ERROR)
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
                              UdpTransportTarget((ip, port)),
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
                              ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.14')), # Входящие ошибки IF-MIB::ifInErrors.X
                              # ObjectType(ObjectIdentity('IF-MIB','ifInUnknownProtos')), # Входящие НЕИЗВЕСТНЫЕ IF-MIB::ifInUnknownProtos.X 1.3.6.1.2.1.2.2.1.15
                              ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.16')),# Исходящие октеты IF-MIB::ifOutOctets.X 1.3.6.1.2.1.2.2.1.16
                              # ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.17')), # Исходящие ifOutUcastPkts IF-MIB::ifOutUcastPkts.X
                              # ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.18')), # Исходящие НЕ ЮНИКАСТ ifOutNUcastPkts IF-MIB::ifOutNUcastPkts.X
                              # ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.19')), # Исходящие ifOutDiscards IF-MIB::ifOutDiscards.X
                              #ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.20')), # Исходящие ошибки IF-MIB::outInErrors.X
                              lexicographicMode=False):

        if errorIndication:
            print(errorIndication)
            break
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
        ports[tmp_array[0]] = tmp_array[1:length]
        del tmp_array[0:length]

    return ports


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
                              UdpTransportTarget((ip, port),timeout=1, retries=5, tagList=''),
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

    #for string in raw_answers:
    #    print(string)
    #sys.exit(1)

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
                interface = string[1]
                mac = re.findall('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$', string[0])[0]
                #mac_original = mac
                mac = mac_to_hex(mac)
                mac_table.append([mac, interface, VLAN_ID])
                fdb_table[interface] = []
                #print([mac, mac_original, string[1], VLAN_ID])

    for string in mac_table:
        port_number = str(string[1])
        fdb_table[port_number] = fdb_table.get(port_number) + [[str(string[0]),str(string[2])]]
    return fdb_table, vlans


if __name__ == "__main__":
    IP_ADDRESS=user_input()
    COMMUNITY='public'
    PORT='161'

    SWITCH_DESCRIPTION = snmp_get(COMMUNITY, IP_ADDRESS, PORT, '1.3.6.1.2.1.1.1.0')  #1.3.6.1.2.1.1.1 - system descr
    SWITCH_UPTIME_time_tick = snmp_get(COMMUNITY, IP_ADDRESS, PORT, '1.3.6.1.2.1.1.3.0') #1.3.6.1.2.1.1.3 - uptime
    print(SWITCH_DESCRIPTION, '  Time tick', SWITCH_UPTIME_time_tick,'\n')

    FDB_TABLE,VLANS = get_fdb_table(COMMUNITY,IP_ADDRESS,PORT)
    SWITCH_PORTS = get_if_stat(COMMUNITY,IP_ADDRESS,PORT)
    for vlan in VLANS:
        VLAN_ID = vlan[0]
        VLAN_HOSTS_AMOUNT = vlan[1]
        print('VLAN ID:', VLAN_ID, '\tКоличество хостов во vlan\'e - ', VLAN_HOSTS_AMOUNT)

    print('Статистика портов')
    for key in SWITCH_PORTS:
        print('Порт: ', key, ' ', SWITCH_PORTS[key])

    print('FDB таблица')
    for key in FDB_TABLE:
        print('Порт: ',key,' ',FDB_TABLE[key])
