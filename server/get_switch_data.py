#!/usr/bin/python3.6
# -*- coding: utf-8 -*-

import re
from sys import exit
import pymysql
from time import localtime, strftime
import time
import datetime
from pysnmp.hlapi import *


def add_new_switch():
    print('Добавляю свитч')


def snmp_walk_2c(community, ip, port, oid):
    raw_answer = []
    object_type = ObjectType(ObjectIdentity(oid))
    for (errorIndication,
         errorStatus,
         errorIndex,
         varBinds) in nextCmd(SnmpEngine(),
                              CommunityData(community, mpModel=1),
                              UdpTransportTarget((ip, port), timeout=10),
                              ContextData(),
                              object_type,
                              ignoreNonIncreasingOid=True,
                              lexicographicMode=False):

        if errorIndication:
            print(errorIndication, ip)
            break

        elif errorStatus:
            print('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex) - 1][0] or '?'), ip)
            break
        else:
            for varBind in varBinds:
                raw_answer.append(' = '.join([x.prettyPrint() for x in varBind]))
    return raw_answer


def get_switch_data(community, switch_list, port):

    switches = []

    for ip in switch_list:

        raw_interfaces = []
        error_occured = False

        for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(SnmpEngine(),
                              CommunityData(community, mpModel=1),
                              UdpTransportTarget((ip, port), timeout=3),
                              ContextData(),
                              # Статистика интерфейсов
                              ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.1')),  # Номер порта IF-MIB::ifIndex.X
                              ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.2')),
                              ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.5')),  # Скорость порта IF-MIB::ifSpeed.X
                              ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.6')),  # Мак адрес порта IF-MIB::ifPhysAddress.X '1.3.6.1.2.1.2.2.1.6'
                              ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.8')),  # Оперативный статус IF-MIB::ifOperStatus.X
                              ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.9')),  # Последнее ищменение состояния IF-MIB::ifLastChange.X
                              ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.10')), # Входящие октеты IF-MIB::ifInOctets.X
                              ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.16')),
                              lexicographicMode=False):

            if errorIndication:
                print(errorIndication, ip )
                error_occured = True
                break

            elif errorStatus:
                print('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex) - 1][0] or '?'), ip)
                error_occured = True
                break
            else:
                raw_interfaces.append([x.prettyPrint() for x in varBinds])

        if error_occured:
            continue

        raw_description = snmp_walk_2c(community, ip, port, '1.3.6.1.2.1.1.1')
        raw_switch_uptime = snmp_walk_2c(community, ip, port, '1.3.6.1.2.1.1.3') #1.3.6.1.2.1.1.3
        raw_vlan_list = snmp_walk_2c(community, ip, port, '1.3.6.1.2.1.17.7.1.2.1.1.2')
        raw_fdb = snmp_walk_2c(community, ip, port, '1.3.6.1.2.1.17.7.1.2.2.1.2')
        raw_arp = snmp_walk_2c(community, ip, port, '1.3.6.1.2.1.4.22.1.2') #! IP-MIB.ipNetToMediaPhysAddress
        raw_lldp = snmp_walk_2c(community, ip, port, '1.0.8802.1.1.2.1.4.1.1')
        #1.3.6.1.4.1.171.11.55.2.2.1.4.3    - Загрузка CPU за пять минут на DGS-3312SR
        #1.3.6.1.4.1.171.12.1.1.6.3         - Загрузка CPU за пять минут на DGS-3420-52T
        switch = {
            'request date': strftime("%Y-%m-%d %H:%M:%S", localtime()),
            'ip address': ip,
            'raw description': raw_description,
            'raw switch uptime': raw_switch_uptime,
            'raw interfaces': raw_interfaces,
            'raw vlan list': raw_vlan_list,
            'raw fdb': raw_fdb,
            'raw arp': raw_arp,
            'raw lldp': raw_lldp
        }
        switches.append(switch)

    return switches


def parse_switch_data(db_address, user, password, db_name, charset, switch_data):

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

    switches = []
    for switch in switch_data:

        switch_request_date = switch['request date']
        switch_ip = switch['ip address']

        interfaces = {}
        vlans = {}
        arp_table = {}
        fdb_table = {}
        lldp_table = {}
        raw_interfaces = switch['raw interfaces']
        raw_lldp = switch['raw lldp']

        for lldp_string in raw_lldp:

            oid, value = lldp_string.split(' = ')

            localPort_mac = re.findall('\.0\.8802\.1\.1\.2\.1\.4\.1\.1\.5\.', oid)
            localPort_destPort = re.findall('\.0\.8802\.1\.1\.2\.1\.4\.1\.1\.7\.', oid)

            if localPort_mac: # Определяю номер порта локального свитча и мак адрес удаленного свитча
                localPort = re.findall('\.[0-9]{1,3}\.[0-9]{1,3}$', oid)[0].split('.')[1]
                mac_dashStyle = re.findall('-', value)
                mac_hexStyle = re.findall('0x', value)

                if mac_hexStyle:
                    mac = value[2:4] + ':' + value[4:6] + ':' + value[6:8] + ':' \
                     + value[8:10] + ':' + value[10:12] + ':' + value[12:14]
                    mac = mac.upper()
                elif mac_dashStyle:
                    mac_dash = value.upper().split('-')
                    mac = mac_dash[0] + ':' + mac_dash[1] + ':' + mac_dash[2] + ':' \
                            + mac_dash[3] + ':' + mac_dash[4] + ':' + mac_dash[5]
                else:
                    mac = value
                    print('MAC адрес не распознан', mac)

                lldp_table[int(localPort)] = {'neighbor mac': mac}


            if localPort_destPort: # Определяю имя порта удаленного свитча
                localPort = re.findall('\.[0-9]{1,3}\.[0-9]{1,3}$', oid)[0].split('.')[1]
                host_port = lldp_table[int(localPort)]['neighbor mac']

                lldp_table[int(localPort)] = {
                    'neighbor port': value,
                    'neighbor mac': host_port
                                              }

        for interface in raw_interfaces:

            if_number = interface[0].split(' = ')[1]
            if_descr = interface[1].split(' = ')[1]
            if_speed = interface[2].split(' = ')[1]
            if_mac = interface[3].split(' = ')[1].upper()
            if_mac = if_mac[2:4] + ':' + if_mac[4:6] + ':' + if_mac[6:8] + ':' \
                     + if_mac[8:10] + ':' + if_mac[10:12] + ':' + if_mac[12:14]
            if_state = interface[4].split(' = ')[1]
            if_uptime = interface[5].split(' = ')[1]
            if_uptime = str(datetime.timedelta(seconds=(int(if_uptime) / 100)))
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
            vlans[int(vid)] = {
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
            # Оптимизировать! Использовать либо одну регулярку либо еще че придумать
            vlan = re.findall('[0-9]{1,5}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$', mac)[0].split('.')[0]
            mac = re.findall('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$', mac)[0].upper()
            mac = __mac_to_hex(mac)
            try:
                host_ip = arp_table[mac].get('host ip')
            except KeyError:
                host_ip = 'Unknown'
            host = []
            host.append((mac, vlan, host_ip))
            try:
                fdb_table[int(port)] = {
                    'hosts' : fdb_table[int(port)]['hosts'] + host
                }
            except KeyError:
                fdb_table[int(port)] = {
                    'hosts': host
                }

        raw_description = switch['raw description']
        raw_switch_uptime = switch['raw switch uptime']
        switch_description = raw_description[0].split(' = ')[1]
        switch_uptime = datetime.timedelta(seconds=(int(raw_switch_uptime[0].split(' = ')[1]) / 100))

        switch_info = {
            'request date': switch_request_date,
            'ip address': switch_ip,
            'switch description': switch_description,
            'switch uptime': switch_uptime,
            'lldp table': lldp_table,
            'interfaces': interfaces,
            'vlans': vlans,
            'fdb table': fdb_table,
        }

        switches.append(switch_info)

    switches_no_id =[]
    ports_table = []

    # Подключиться к базе данных.
    # Добавляю актуальную информацию по свитчам и портам из БД
    # switch_id, ip_ports и значение последнего id_requests для каждого из свитчей
    try:
        connection = pymysql.connect(host=db_address, user=user, password=password,
                                     db=db_name, charset=charset, cursorclass=pymysql.cursors.DictCursor)

        # SQL - запросы
        get_switches = "SELECT * FROM switches"
        get_ports = "SELECT * FROM ports"

        try:
            with connection.cursor() as cursor:
                # 1. Взять всю таблицу свитчей
                cursor.execute(get_switches)
                switches_table = cursor.fetchall()

                # 2. Взять все порты свитчей
                cursor.execute(get_ports)
                ports_table = cursor.fetchall()

                # 3. Получить последние id_requests для свитча и синхронизировать, если они будут разниться.
                for switch in switches:

                    switch_ip = switch['ip address']

                    for switch_tb in switches_table:  # Получаю id switch для каждого свитча
                        if switch_tb['ip'] == switch_ip:
                            id_switches = switch_tb['id_switches']
                            switch['switch id'] = id_switches  # Добавляю id свитча в словарь свитча
                            break

                    if switch['switch id']:
                        get_max_id_requests = """ 
                                            SELECT max(id_requests) FROM statistics_switch 
                                            where id_switches = '%(id_switches)s'""" % {"id_switches": switch['switch id']}

                    # ВВЕСТИ ПРОВЕРКУ НА ИЗМЕНЕНИЕ IP адреса - т.е. id свитча старый, но ip изменился!

                        cursor.execute(get_max_id_requests)
                        last_id_request = cursor.fetchone()
                        switch['last id request'] = last_id_request['max(id_requests)']
                        switch['last id request statistics_ports '] = ''

                    else:
                        print('В БД нет такого свитча:', switch_ip)
                        switches_no_id.append(switch)
                        continue

        finally:
            connection.close()

    except pymysql.err.OperationalError as operror:
        print('Ошибка соединения с mysql', operror)
        exit(1)

    # Удаляю из списка свитчей - свитч без id_switches
    switches = [switch for switch in switches if switch not in switches_no_id ]

    for switch in switches:

        # Временные словари для парсинга
        switch_ip = switch['ip address']
        switch_if = switch['interfaces']
        switch_fdb = switch['fdb table']
        switch_lldp = switch['lldp table']

        switch_ports = []  # Выбираю только порты данного свитча из общей солянки
        for port in ports_table:
            if port['id_switches'] == switch['switch id']:
                switch_ports.append(port)

        for port in switch_ports:  # Добавляю 'port id' для каждого порта из словарей interfaces и fdb_table
            id_ports, port_number = port['id_ports'], port['port_number'] # id и номер порта  конкретного свитча

            try:
                switch_if[int(port_number)]['port id'] = id_ports   # Добавляю ключ 'port id' во временный словарь для интерфейсов свитча

                try:    # Добавляю ключ 'port id' во временный словарь для FDB таблицы
                    switch_fdb[int(port_number)]['port id'] = id_ports
                except KeyError:
                    continue

                try:    # Добавляю ключ 'port id' во временный словарь для LLDP таблицы
                    switch_lldp[int(port_number)]['port id'] = id_ports
                except KeyError:
                    continue

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
        switch['fdb table'] = switch_fdb

    return switches


def insert_db(db_address, user, password, db_name, charset, switches):

    for switch in switches:

        #id_request = ''

        request_date = switch['request date']
        switch_ip = switch['ip address']
        switch_id = switch['switch id']
        switch_uptime = switch['switch uptime']
        switch_descr = switch['switch description']
        switch_vlans = switch['vlans']
        switch_if = switch['interfaces']
        switch_fdb = switch['fdb table']
        switch_lldp = switch['lldp table']

        print(switch_ip)

        insert_time_request = "INSERT requests(DATE) value('%(request_date)s')" % {"request_date": request_date}
        get_id_requests = "SELECT max(id_requests) FROM requests"


        # Подключиться к базе данных.
        try:
            connection = pymysql.connect(host=db_address, user=user, password=password, db=db_name,
                                     charset=charset, cursorclass=pymysql.cursors.DictCursor)

            cursor = connection.cursor()
            # Записать время опроса свитчей и взять id этого запроса
            cursor.execute(insert_time_request)
            connection.commit()

            cursor.execute(get_id_requests)
            id_request = cursor.fetchone()
            id_request = id_request['max(id_requests)']

        except pymysql.err.OperationalError as operror:
            print('Ошибка соединения с mysql', operror)
            continue

        vlan_tuples = []
        for vlan in sorted(switch_vlans):
            tupe = (vlan, int(switch_vlans[vlan]['host amount']), switch_id, id_request)
            vlan_tuples.append(tupe)

        interface_tuples = []
        for interface in sorted(switch_if):
            try:
                tupe = (switch_if[interface]['port id'], switch_if[interface]['interface description'],
                    switch_if[interface]['interface speed'], switch_if[interface]['interface mac'],
                    switch_if[interface]['interface status'], switch_if[interface]['interface uptime'],
                    switch_if[interface]['interface in Bytes'], switch_if[interface]['interface out Bytes'],
                    id_request)

                interface_tuples.append(tupe)
            except KeyError:
                print('У свитча есть interface, которого нет в нашей БД', '\n',
                      interface, '\n',
                      switch_if[interface]
                      )
                continue

        fdb_tuples = []
        for fdb_string in sorted(switch_fdb):
            try:
                id_port_req = ( id_request, switch_fdb[fdb_string]['port id'],)
                hosts = switch_fdb[fdb_string]['hosts']
                for host in hosts:
                    fdb_tuples.append((id_port_req + host))
            except KeyError:
                print('Нет id port: ', fdb_string, switch_fdb[fdb_string])

        lldp_tuples = []
        for port_number in sorted(switch_lldp):
            try:
                lldp_tuples.append((switch_lldp[port_number]['port id'], switch_lldp[port_number]['neighbor mac'], switch_lldp[port_number]['neighbor port'], id_request))
            except KeyError as error_key:
                print(switch_id, error_key)

        try:
            with connection.cursor() as cursor:

                # statistics_switch
                insert_statistics_switch = """ 
                    INSERT statistics_switch(id_switches, id_requests, switch_description, switch_uptime) 
                    values('%(id_switches)s', '%(id_requests)s', '%(switch_description)s', '%(switch_uptime)s')""" \
                    % {"id_switches": switch_id, "id_requests": id_request, "switch_description": switch_descr,
                       "switch_uptime": switch_uptime}

                insert_vlan_table = """ 
                    INSERT vlan_table(VID, host_amount, id_switches, id_requests ) 
                        values(%s, %s, %s, %s) """

                # statistics_ports
                insert_statistics_ports = """ 
                    INSERT statistics_ports(id_ports, port_description, port_speed, port_mac, 
                        port_status, port_uptime, port_in_octets, port_out_octets, id_requests) 
                    values(%s, %s, %s, %s, %s, %s, %s, %s, %s) """

                # FDB_tables
                insert_fdb_tables = """ 
                    INSERT FDB_tables(id_requests, id_ports, mac_address, VID, ip_address) 
                    values(%s, %s, %s, %s, %s)"""

                #LLDP table
                insert_lldp_table = """ 
                    INSERT LLDP_table(id_ports, neighbor_mac, neighbor_port, id_requests) 
                    values(%s, %s, %s, %s)"""

                cursor.execute(insert_statistics_switch)
                cursor.executemany(insert_vlan_table, vlan_tuples)
                cursor.executemany(insert_statistics_ports, interface_tuples)
                cursor.executemany(insert_fdb_tables, fdb_tuples)
                cursor.executemany(insert_lldp_table, lldp_tuples)

        finally:
            connection.commit() # Записать изменения в БД
            connection.close()


def update_db(db_address, user, password, db_name, charset, switches):
    for switch in switches:

        request_date = switch['request date']
        last_id_request = switch['last id request']
        last_id_request_ports = ''
        last_id_request_FDB = ''
        last_id_request_LLDP = ''
        current_id_request = ''

        switch_ip = switch['ip address']
        switch_id = switch['switch id']
        switch_uptime = switch['switch uptime']
        switch_descr = switch['switch description']
        switch_vlans = switch['vlans']
        switch_if = switch['interfaces']
        switch_fdb = switch['fdb table']
        switch_lldp = switch['lldp table']

        vid_array = []
        id_ports_switch_array = []
        id_ports_statistics_array = []
        id_ports_FDB_tables_array = []
        id_ports_LLDP_table_array = []

        print(switch_ip)

        # Добавить новый id_requests в БД
        try:

            insert_time_request = "INSERT requests(DATE) value('%(request_date)s')" % {"request_date": request_date}
            get_id_requests = "SELECT max(id_requests) FROM requests"

            connection = pymysql.connect(host=db_address, user=user, password=password, db=db_name,
                                     charset=charset, cursorclass=pymysql.cursors.DictCursor)

            cursor = connection.cursor()
            # Записать время опроса свитча
            cursor.execute(insert_time_request)
            connection.commit()

            # Взять id этого запроса
            cursor.execute(get_id_requests)
            current_id_request = cursor.fetchone()
            current_id_request = current_id_request['max(id_requests)']
            connection.close()

            print('новый id_request', current_id_request)

        except pymysql.err.OperationalError as operror:
            print('Ошибка соединения с mysql', operror)
            continue

        # Получить последние данные по свитчу
        try:
            connection = pymysql.connect(host=db_address, user=user, password=password,
                                         db=db_name, charset=charset, cursorclass=pymysql.cursors.DictCursor)

            get_statistics_switch = """ 
                    SELECT * FROM statistics_switch 
                        inner join requests using(id_requests) 
                        where id_switches = '%(switch_id)s' 
                        and id_requests = '%(last_id_request)s' """ % {"switch_id": switch_id,
                                                                       "last_id_request": last_id_request}

            get_statistics_ports = """
                    SELECT id_requests, id_ports FROM ports 
                        inner join statistics_ports using(id_ports)
                        inner join requests using(id_requests) 
                        WHERE id_switches = '%(switch_id)s'
                        and id_requests = (SELECT max(id_requests) 
                            FROM (
                                SELECT * FROM ports inner join 
                                statistics_ports using(id_ports)
                                inner join requests using(id_requests) 
						        WHERE id_switches = '%(switch_id)s'
                                ) as tmp
                        );""" % {"switch_id": switch_id}

            get_FDB_tables = """           
                    SELECT id_requests, id_ports FROM 
                    ports inner join 
                    FDB_tables using(id_ports) inner join 
                    requests using(id_requests) 
                    WHERE id_switches = '%(switch_id)s' 
                    and id_requests = (select max(id_requests) from (
                        SELECT * FROM 
                        ports inner join 
                        FDB_tables using(id_ports) inner join 
                        requests using(id_requests) 
                        WHERE id_switches = '%(switch_id)s' 
                        ) as tmp 
                    );""" % {"switch_id": switch_id}

            get_vlan_table = """
                    SELECT VID FROM vlan_table 
                        inner join requests using(id_requests) 
                        where id_switches = '%(switch_id)s' 
                        and id_requests = '%(last_id_request)s' """ % {"switch_id": switch_id,
                                                                       "last_id_request": last_id_request}

            get_LLDP_table = """
                    SELECT id_requests, id_ports FROM ports 
                        inner join LLDP_table using(id_ports)
                        inner join requests using(id_requests) 
                        WHERE id_switches = '%(switch_id)s'
                        and id_requests = (SELECT max(id_requests) 
                            FROM (
                                SELECT * FROM 
                                ports inner join 
                                LLDP_table using(id_ports)
                                inner join requests using(id_requests) 
						        WHERE id_switches = '%(switch_id)s'
                                ) as tmp
                            );""" % {"switch_id": switch_id}
            try:
                with connection.cursor() as cursor:

                    # 1. Взять статистику свитча
                    #cursor.execute(get_statistics_switch)
                    #statistics_ports = cursor.fetchall()

                    # 1. Взять статичтику портов
                    cursor.execute(get_statistics_ports)
                    id_ports_ports_statistic = cursor.fetchall()

                    # 2. Взять FDB таблицу свитча
                    cursor.execute(get_FDB_tables)
                    id_ports_FDB_tables = cursor.fetchall()

                    # 3. Взять таблицу vlan
                    cursor.execute(get_vlan_table)
                    vid_vlan_table = cursor.fetchall()

                    # 4. Взять LLDP таблицу
                    cursor.execute(get_LLDP_table)
                    id_ports_LLDP_table = cursor.fetchall()

                    for element in vid_vlan_table:
                        vid_array.append(int(element['VID']))

                    for element in id_ports_ports_statistic:
                        last_id_request_ports = element['id_requests']
                        id_ports_statistics_array.append(int(element['id_ports']))

                    for element in id_ports_FDB_tables:
                        last_id_request_FDB = element['id_requests']
                        id_ports_FDB_tables_array.append(int(element['id_ports']))

                    for element in id_ports_LLDP_table:
                        last_id_request_LLDP = element['id_requests']
                        id_ports_LLDP_table_array.append(int(element['id_ports']))

                    print('last id request', last_id_request, 'таблица vlan', vid_vlan_table)
                    print('last_id_request_ports', last_id_request_ports, 'статиcтика портов', id_ports_statistics_array)
                    print('last_id_request_FDB', last_id_request_FDB, 'FDB таблица', id_ports_FDB_tables_array)
                    print('last_id_request_LLDP', last_id_request_LLDP, 'LLDP таблица', id_ports_LLDP_table_array)

            finally:
                connection.close()

        except pymysql.err.OperationalError as operror:
            print('Ошибка соединения с mysql', operror)
            exit(1)

        # Разобрать данные на кортежи
        vlan_update = []
        vlan_insert = []
        vlan_tuples_update = []
        vlan_tuples_insert = []

        # Отбираю элементы VID, которые нужно будет обновить, а не вставить
        for element in vid_array:
            if element in sorted(switch_vlans):
                vlan_update.append(element)
            else:
                vlan_insert.append(element)

        for vlan in sorted(switch_vlans):
            if vlan in vlan_update:
                tupe_vlan_update = (int(switch_vlans[vlan]['host amount']), current_id_request, switch_id, last_id_request, vlan)
                #print(tupe_vlan_update)
                vlan_tuples_update.append(tupe_vlan_update)
            else:
                tupe_vlan_insert = (vlan, int(switch_vlans[vlan]['host amount']), switch_id, current_id_request)
                vlan_tuples_insert.append(tupe_vlan_insert)

        update_vlan_table = """ 
            UPDATE vlan_table SET 
                host_amount = %s, id_requests = %s
                WHERE id_switches = %s
                AND id_requests = %s
                AND VID = %s;
                """

        insert_vlan_table = """ 
            INSERT vlan_table(VID, host_amount, id_switches, id_requests ) 
                values(%s, %s, %s, %s) """

        # Отбираю элементы id_ports для таблицы statistics_ports
        ports_statistic_update = []
        ports_statistic_insert = []
        ports_statistic_tuples_update = []
        ports_statistic_tuples_insert = []

        for key in sorted(switch_if):
            id_ports_switch_array.append(switch_if[key]['port id'])

        for element in id_ports_statistics_array:
            if element in id_ports_switch_array:
                ports_statistic_update.append(element)
            else:
                ports_statistic_insert.append(element)

        for interface in sorted(switch_if):
            if interface in ports_statistic_update:
                try:

                    tuple_ports_statistics_update = (
                                             switch_if[interface]['interface description'],
                                             switch_if[interface]['interface speed'],
                                             switch_if[interface]['interface mac'],
                                             switch_if[interface]['interface status'],
                                             switch_if[interface]['interface uptime'],
                                             switch_if[interface]['interface in Bytes'],
                                             switch_if[interface]['interface out Bytes'],
                                             current_id_request,
                                             switch_if[interface]['port id'],
                                             last_id_request_ports)

                    ports_statistic_tuples_update.append(tuple_ports_statistics_update)

                except KeyError:
                    print('У свитча есть interface, которого нет в нашей БД', '\n',
                          interface, '\n',
                          switch_if[interface]
                          )
                    continue

            else:

                try:

                    tuple_ports_statistics_insert = (switch_if[interface]['port id'], switch_if[interface]['interface description'],
                            switch_if[interface]['interface speed'], switch_if[interface]['interface mac'],
                            switch_if[interface]['interface status'], switch_if[interface]['interface uptime'],
                            switch_if[interface]['interface in Bytes'], switch_if[interface]['interface out Bytes'],
                            current_id_request)

                    ports_statistic_tuples_insert.append(tuple_ports_statistics_insert)

                except KeyError:
                    print('У свитча есть interface, которого нет в нашей БД', '\n',
                          interface, '\n',
                          switch_if[interface]
                          )
                    continue

        update_statistics_ports = """ 
                            UPDATE statistics_ports SET
                                port_description = %s, 
                                port_speed = %s, 
                                port_mac = %s, 
                                port_status = %s, 
                                port_uptime = %s, 
                                port_in_octets = %s, 
                                port_out_octets = %s, 
                                id_requests = %s
                                WHERE id_ports = %s
                                AND id_requests = %s;
                                """
        insert_statistics_ports = """ 
                                INSERT statistics_ports(id_ports, 
                                                        port_description, 
                                                        port_speed, port_mac, 
                                                        port_status, 
                                                        port_uptime, 
                                                        port_in_octets, 
                                                        port_out_octets, 
                                                        id_requests) 
                                values(%s, %s, %s, %s, %s, %s, %s, %s, %s) """

        ports_fdb_tables_update = []
        ports_fdb_tables_insert = []
        ports_fdb_tables_tuples_update = []
        ports_fdb_tables_tuples_insert = []
        id_ports_switch_array = []

        for key in sorted(switch_fdb):
            try:
                id_ports_switch_array.append(switch_fdb[key]['port id'])

            except KeyError:
                continue

        for element in sorted(id_ports_FDB_tables_array):
            if element in id_ports_switch_array:
                ports_fdb_tables_update.append(element)
            else:
                ports_fdb_tables_insert.append(element)

        for port in sorted(switch_fdb):
            try:
                id_ports = switch_fdb[port]['port id']
                if id_ports in ports_fdb_tables_update:
                    hosts = switch_fdb[port]['hosts']
                    for host in hosts:
                        ports_fdb_tables_tuples_update.append(
                            (current_id_request,
                             id_ports,
                             host[0],
                             host[1],
                             host[2],
                             id_ports,
                             last_id_request_FDB))
                else:
                    hosts = switch_fdb[port]['hosts']
                    for host in hosts:
                        ports_fdb_tables_tuples_insert.append(
                            (current_id_request,
                             id_ports,
                             host[0],
                             host[1],
                             host[2])
                        )
            except KeyError:
                print('Нет id port: ', port, switch_fdb[port])

        update_fdb_tables = """
                UPDATE FDB_tables SET
                    id_requests = %s,
                    id_ports = %s,
                    mac_address = %s,
                    VID = %s,
                    ip_address = %s
                    WHERE id_ports = %s
                    AND id_requests = %s; 
                """

        insert_fdb_tables = """ 
                INSERT FDB_tables(
                    id_requests, 
                    id_ports, 
                    mac_address, 
                    VID, 
                    ip_address) 
                    values(%s, %s, %s, %s, %s)"""

        id_ports_switch_array = []
        ports_lldp_table_update = []
        ports_lldp_table_insert = []
        ports_lldp_table_tuples_update = []
        ports_lldp_table_tuples_insert = []

        for key in sorted(switch_lldp):
            id_ports_switch_array.append(switch_lldp[key]['port id'])

        for element in id_ports_LLDP_table_array:
            if element in id_ports_switch_array:
                ports_lldp_table_update.append(element)
            else:
                ports_lldp_table_insert.append(element)

        lldp_tuples = []
        for port_number in sorted(switch_lldp):
            try:
                if switch_lldp[port_number]['port id'] in ports_lldp_table_update:
                    ports_lldp_table_tuples_update.append(
                        (switch_lldp[port_number]['port id'],
                         switch_lldp[port_number]['neighbor mac'],
                         switch_lldp[port_number]['neighbor port'],
                         current_id_request,
                         switch_lldp[port_number]['port id'],
                         last_id_request_LLDP)
                    )

                else:
                    ports_lldp_table_tuples_insert.append(
                        (switch_lldp[port_number]['port id'],
                         switch_lldp[port_number]['neighbor mac'],
                         switch_lldp[port_number]['neighbor port'],
                         current_id_request)
                    )

            except KeyError as error_key:
                print(switch_id, error_key)

        # LLDP table

        update_lldp_table = """
                UPDATE LLDP_table SET
                    id_ports = %s, 
                    neighbor_mac = %s, 
                    neighbor_port = %s, 
                    id_requests = %s
                    WHERE id_ports = %s
                    AND id_requests = %s
                """

        insert_lldp_table = """ 
                INSERT LLDP_table(
                    id_ports, 
                    neighbor_mac, 
                    neighbor_port, 
                    id_requests) values(%s, %s, %s, %s)"""

        # Записать обновленные значения
        try:
            connection = pymysql.connect(host=db_address, user=user, password=password,
                                         db=db_name, charset=charset, cursorclass=pymysql.cursors.DictCursor)

            # statistics_switch
            update_statistics_switch = """ 
                                UPDATE statistics_switch SET 
                                    id_requests = '%(id_requests)s',
                                    switch_description = '%(switch_description)s',
                                    switch_uptime = '%(switch_uptime)s'
                                    WHERE id_switches = '%(id_switches)s'
                                    AND id_requests = '%(last_id_request)s'
                                    """ \
                                       % {"id_switches": switch_id, "id_requests": current_id_request,
                                          "last_id_request": last_id_request,"switch_description": switch_descr,
                                          "switch_uptime": switch_uptime}

            cursor = connection.cursor()
            cursor.execute(update_statistics_switch)
            cursor.executemany(update_vlan_table, vlan_tuples_update)
            if len(vlan_tuples_insert) != 0:
                cursor.executemany(insert_vlan_table, vlan_tuples_insert)

            cursor.executemany(update_statistics_ports, ports_statistic_tuples_update)
            print('Обновление, статистика портов', ports_statistic_update)
            if len(ports_statistic_insert) != 0:
                print('Вставка, статистика портов', ports_statistic_insert)
                cursor.executemany(insert_statistics_ports, ports_statistic_tuples_insert)

            cursor.executemany(update_fdb_tables, ports_fdb_tables_tuples_update)
            print('Обновление, FDB таблица', ports_fdb_tables_update)
            if len(ports_fdb_tables_insert) != 0:
                print('Вставка, FDB таблица', ports_fdb_tables_insert)
                cursor.executemany(insert_fdb_tables, ports_fdb_tables_tuples_insert)

            cursor.executemany(update_lldp_table, ports_lldp_table_tuples_update)
            print('Обновление, LLDP таблица', ports_lldp_table_update)
            if len(ports_lldp_table_insert) != 0:
                cursor.executemany(insert_lldp_table, ports_lldp_table_tuples_insert)
                print('Вставка, LLDP таблица', ports_lldp_table_insert)

        finally:
            connection.commit()  # Записать изменения в БД
            connection.close()


if __name__ == "__main__":

    snmp_agent = {
        'community': 'public',
        'port': 161,
    }

    cred = {
        'host': '10.4.5.54',
        'user': 'pysnmp',
        'passwd': '123456',
        'db': 'switch_snmp_lldp_t1',
        'charset': 'utf8',
    }

    SWITCH_WORKSHOP = ['10.4.0.200', '10.4.0.201', '10.4.0.202', '10.4.0.203',
                       '10.4.0.204', '10.4.0.205', '10.4.0.206', '10.4.0.207', '10.4.0.208',
                       '10.4.0.209', '10.4.0.210', '10.4.0.211', '10.4.0.212',
                       '10.4.0.213', '10.4.0.214', '10.4.0.215', '10.4.0.217', '10.4.0.218']

    SWITCH_ABK = ['10.4.0.1', '10.4.100.12', '10.4.100.13', '10.4.100.111',
                  '10.4.100.121', '10.4.100.131', '10.4.100.171', '10.4.100.211',
                  '10.4.100.212', '10.4.100.213', '10.4.100.215', '10.4.100.216',
                  '10.4.100.231', '10.4.100.251']

    N16_SWITCHES = ['10.1.13.249', '10.1.13.252']

    SWITCHES_IZ2 = SWITCH_WORKSHOP + SWITCH_ABK

    start1 = time.time()
    switch_raw = get_switch_data(snmp_agent['community'], SWITCHES_IZ2, snmp_agent['port'])
    end1 = time.time()

    start2 = time.time()
    switches = parse_switch_data(cred['host'], cred['user'], cred['passwd'], cred['db'], cred['charset'], switch_raw)
    #for switch in switches:
    #    for key in sorted(switch['lldp table']):
    #        print(key, switch['lldp table'][key])
    end2 = time.time()

    start3 = time.time()
    update_db(cred['host'], cred['user'], cred['passwd'], cred['db'], cred['charset'], switches)
    #insert_db(cred['host'], cred['user'], cred['passwd'], cred['db'], cred['charset'], switches)
    end3 = time.time()

    print('\n',
          'Сбор данных: ', datetime.timedelta(seconds=(int(end1 - start1))), '\n',
          'Парсинг данных: ', round(int(end2 - start2), 12), 'секунд', '\n',
          'Запись в БД:', round(int(end3 - start3), 5), 'секунд','\n',
          'Общее время: ', datetime.timedelta(seconds=(int(end3 - start1))), '\n'
          )
