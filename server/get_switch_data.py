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


def snmp_switch(community, switch_list, port): # Функция опроса свитчей по SNMP

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


def get_actual_db_data(db_address, user, password, db_name, charset, switches):
    # Взять актуальную информацию из БД
    # свитчи и порты,
    # актуальные записи FDB, LLDP, статистику портов, таблицу vlan, статистику портов

    connection = pymysql.connect(host=db_address, user=user, password=password,
                                 db=db_name, charset=charset, cursorclass=pymysql.cursors.DictCursor)

    switches_no_id = []

    try:
        with connection.cursor() as cursor:

            for switch in switches:

                database_error = 0

                switch_ip = switch['ip address'] # string
                switch_if_stat = switch['interfaces']  # dic статистика портов
                switch_fdb = switch['fdb table'] # dic
                switch_lldp = switch['lldp table'] # dic
                switch_vlan = switch['vlans']
                request_date = switch['request date']

                get_switches_ports = """
                        SELECT * FROM switches
                            inner join ports using(id_switches) where ip = '%(switch_ip)s'""" % {"switch_ip": switch_ip}

                cursor.execute(get_switches_ports)
                table_sw_ports = cursor.fetchall()

                if type(table_sw_ports) != list:
                    print('Свитча с таким ip: ', switch_ip, 'не найдено')
                    switches_no_id.append(switch) # Добавляю свитч в список для удаления из опроса
                    continue

                switch_id = table_sw_ports[0]['id_switches'] # Беру switch_id из первой записи

                for string in table_sw_ports: #проверка на id свитча, чтобы все id свитча были одинаковыми
                    if switch_id != string['id_switches']:
                        print('У свтча', switch_ip, 'разные id!', string['id_switches'])
                        database_error = database_error + 1
                        break

                if database_error != 0: # Если случилась ошибка связанная с базой данных - пропускаю свитч
                    continue

                # Добавляю в словари необходимую инфу

                switch['id switch'] = switch_id

                for string in table_sw_ports:
                    #print('id port:', string['id_ports'], 'port number:', string['port_number'])

                    try:
                        switch_if_stat[int(string['port_number'])]['port id'] = string['id_ports']

                    except KeyError:
                        #print('IF-stat: Невозможно добавить port id ', string['id_ports'], 'такого порта нет', string['port_number'])
                        continue

                    try:
                        switch_fdb[int(string['port_number'])]['port id'] = string['id_ports']

                        # Временный массив для switch_fdb['hosts']
                        # - туда будут добавлены id_port для каждой записи MAC адреса
                        fdb_hosts_temp = []

                        # Для каждого мак адреса в FDB таблицы добавляю 'port id'
                        for host in switch_fdb[int(string['port_number'])]['hosts']:
                            fdb_hosts_temp.append((int(string['id_ports']), host[0], host[1], host[2]))

                        switch_fdb[int(string['port_number'])]['hosts'] = fdb_hosts_temp

                    except KeyError:
                        """
                        print('FDB: Невозможно добавить port id ', string['id_ports'], 'такого порта нет',
                              string['port_number'])
                        """
                        continue

                    try:
                        switch_lldp[int(string['port_number'])]['port id'] = string['id_ports']

                    except KeyError:
                        """
                        print('LLDP: Невозможно добавить port id ', string['id_ports'], 'такого порта нет',
                              string['port_number'])
                        """
                        continue

                get_id_rqst_if_stat = """
                                    SELECT id_requests FROM ports 
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

                get_id_rqst_fdb = """           
                                                    SELECT id_requests FROM 
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

                get_id_rqst_lldp = """
                                    SELECT id_requests FROM ports 
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

                get_id_rqst_vlan = """
                                    SELECT max(id_requests) FROM vlan_table
                                        WHERE id_switches = '%(switch_id)s'
                                 """ % {"switch_id": switch_id}

                get_id_rqst_sw_stat = """
                                    SELECT max(id_requests) FROM statistics_switch
                                        WHERE id_switches = '%(switch_id)s'
                                 """ % {"switch_id": switch_id}

                insert_time_request = "INSERT requests(DATE) value('%(request_date)s')" % {"request_date": request_date}

                get_id_requests = "SELECT max(id_requests) FROM requests"

                cursor.execute(get_id_rqst_if_stat)
                max_id_rqst_if_stat = cursor.fetchone()

                cursor.execute(get_id_rqst_fdb)
                max_id_rqst_fdb = cursor.fetchone()

                cursor.execute(get_id_rqst_lldp)
                max_id_rqst_lldp = cursor.fetchone()

                cursor.execute(get_id_rqst_vlan)
                max_id_rqst_vlan = cursor.fetchone()

                cursor.execute(get_id_rqst_sw_stat)
                max_id_rqst_sw_stat = cursor.fetchone()

                # Записать время опроса свитчей и взять id этого запроса
                cursor.execute(insert_time_request)
                connection.commit()

                cursor.execute(get_id_requests)
                current_id_request = cursor.fetchone()

                try:
                    switch_if_stat['last id request'] = max_id_rqst_if_stat['id_requests']
                    switch_fdb['last id request'] = max_id_rqst_fdb['id_requests']
                    switch_lldp['last id request'] = max_id_rqst_lldp['id_requests']
                    switch_vlan['last id request'] = max_id_rqst_vlan['max(id_requests)']
                    switch['last id request'] = max_id_rqst_sw_stat['max(id_requests)']
                    switch['current id request'] = current_id_request['max(id_requests)']
                except KeyError:
                    print('Невозможно записать \'last id request\':', switch_ip)
                    switches_no_id.append(switch)
                    break

    except pymysql.err.OperationalError as operror:
        print('Ошибка соединения с mysql', operror)

    finally:
        connection.close()

    # Удаляю из списка свитчей - свитч без id_switches
    switches = [switch for switch in switches if switch not in switches_no_id]

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
                    continue

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
            'request date': switch_request_date, # Время опроса во временном формате
            'ip address': switch_ip,
            'switch description': switch_description,
            'switch uptime': switch_uptime,
            'lldp table': lldp_table,
            'interfaces': interfaces,
            'vlans': vlans,
            'fdb table': fdb_table,
        }

        switches.append(switch_info)

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

        # Текущий запрос, с которым должны быть синхронизированы все остальные в таблицах
        current_id_request = switch['current id request']
        last_id_request = switch['last id request']
        request_date = switch['request date']
        switch_description = switch['switch description']
        switch_uptime = switch['switch uptime']
        id_switch = switch['id switch']
        ip_switch = switch['ip address']
        switch_if_stat = switch['interfaces']
        switch_fdb = switch['fdb table']
        switch_lldp = switch['lldp table']
        switch_vlans = switch['vlans']

        for interface in switch_if_stat:
            print(interface, switch_if_stat[interface])

        for port in switch_fdb:
            print(port, switch_fdb[port])

        for port in switch_lldp:
            print(port, switch_lldp[port])

        for vid in switch_vlans:
            print(vid, switch_vlans[vid])

        update_statistics_sw = """
            UPDATE statistics_switch SET
                id_requests = '%(current_id_request)s',
                switch_description = '%(switch_description)s',
                switch_uptime = '%(switch_uptime)s',
                cpu_utilization = 'no data',
                memory_utilization = 'no data'
                WHERE id_switches = '%(id_switches)s'
                AND id_requests = '%(last_id_request)s'
        """

        update_vlan_table = """
            UPDATE vlan_table SET
                id_requests = '%s',
                id_switches = '%s',
                VID = '%s',
                host_amount = '%s'
                WHERE id_switches = '%s'
                AND id_requests = '%s'
        """

        update_statistics_ports = """
            UPDATE statistics_ports SET
                port_description = '%s',
                port_speed = '%s',
                port_mac = '%s',
                port_status ='%s',
                port_uptime = '%s',
                port_in_octets = '%s',
                port_out_octets = '%s',
                id_requests = '%s'
                WHERE id_ports = '%s'
                AND id_requests = '%s'
        """

        update_LLDP_table = """
            UPDATE LLDP_table SET
                neighbor_mac = '%s',
                neighbor_port = '%s',
                id_requests = '%s'
                WHERE id_ports = '%s'
                AND id_requests = '%s'
        """

        update_FDB_tables = """
            UPDATE FDB_tables SET
                id_requests = '%s',
                mac_address = '%s',
                VID = '%s',
                ip_address = '%s'
                WHERE id_ports = '%s'
                AND id_requests = '%s'
                AND mac_address = '%s'
        """

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
                       '10.4.0.209', '10.4.0.210', '10.4.0.211', '10.4.0.212', '10.4.0.213',
                       '10.4.0.214', '10.4.0.215', '10.4.0.217', '10.4.0.218']

    SWITCH_ABK = ['10.4.0.1', '10.4.100.12', '10.4.100.13', '10.4.100.101',
                  '10.4.100.102', '10.4.100.111', '10.4.100.121', '10.4.100.131',
                  '10.4.100.171', '10.4.100.211', '10.4.100.212', '10.4.100.213',
                  '10.4.100.215', '10.4.100.216', '10.4.100.231', '10.4.100.251']

    N16_SWITCHES = ['10.1.13.249', '10.1.13.252']

    SWITCHES_IZ2 = SWITCH_WORKSHOP + SWITCH_ABK

    start1 = time.time()
    switch_raw = snmp_switch(snmp_agent['community'], ['10.4.0.1'], snmp_agent['port'])
    end1 = time.time()

    start2 = time.time()
    switches = parse_switch_data(switch_raw)
    get_actual_db_data(cred['host'], cred['user'], cred['passwd'], cred['db'], cred['charset'], switches)
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