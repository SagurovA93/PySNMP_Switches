import json
from termcolor import colored
import pymysql


class MonitoringSwitches:
    

    def __init__(self, cred_db):
        
        self.cred_db  = cred_db
        self.switches = {}

        db = pymysql.connect(**self.cred_db)
        cursor = db.cursor()

        self._db_switches_port(cursor)
        self._db_switches_mac(cursor)

        db.close()

        self.all_mac_switches = self._get_all_mac_switches()

        self.switch_to_switch = self._get_switch_to_switch()


    def _db_switches_port(self, cursor):
        
        query_all_switches = '''
            SELECT switches.id_switches, switches.ip, ports.port_number, FDB_tables.mac_address
            FROM switches
            INNER JOIN ports using(id_switches)
            INNER JOIN FDB_tables using(id_ports)
            INNER JOIN requests using(id_requests)
            WHERE requests.DATE = '2018-07-03 16:02:54'#(SELECT MAX(requests.DATE) FROM requests)
        '''
        cursor.execute(query_all_switches)
        data =  cursor.fetchall()

        for switch in data:
            id_switches, ip, port_number, mac = switch

            if self.switches.get(ip) is None:
                self.switches[ip]          = {}
                self.switches[ip]['ports'] = {}
            if self.switches[ip]['ports'].get(port_number) is None:
                self.switches[ip]['ports'][port_number]               = {}
                self.switches[ip]['ports'][port_number]['init_mac']   = set()
                self.switches[ip]['ports'][port_number]['change_mac'] = set()
            
            self.switches[ip]['ports'][port_number]['init_mac'].add(mac.upper())
            self.switches[ip]['ports'][port_number]['change_mac'].add(mac.upper())
            self.switches[ip]['id_switches'] = id_switches


    def _db_switches_mac(self, cursor):
        query_all_switches = '''
            SELECT switches.id_switches, switches.ip, statistics_ports.port_mac
            FROM statistics_ports
            INNER JOIN ports using(id_ports)
            INNER JOIN switches using(id_switches)
            INNER JOIN requests using(id_requests)
            WHERE requests.DATE = '2018-07-03 16:02:54'#(SELECT MAX(requests.DATE) FROM requests);
        '''
        cursor.execute(query_all_switches)
        data =  cursor.fetchall()

        for switch in data:
            id_switches, ip, mac = switch

            if self.switches.get(ip) is None:
                self.switches[ip] = {}
                self.switches[ip]['id_switches'] = id_switches
                print(colored("ERROR: нет портов у %s"%(ip), 'red'))
            if self.switches[ip].get('mac') is None:
                self.switches[ip]['mac'] = set()
            if mac == '00:00:00:00:00:00':
                continue
            self.switches[ip]['mac'].add(mac.upper())


    def _foreach_switches(self, func_handler_port, func_handler_switch=None, switches=None):
        if switches is None:
            switches = self.switches                
        for ip_switch in switches.keys():
            id_switches = switches[ip_switch].get('id_switches')
            mac_swithces = switches[ip_switch].get('mac')

            if func_handler_switch is not None:
                func_handler_switch(id_switches=id_switches, ip_switch= ip_switch, mac_swithces=mac_swithces)
                continue

            ports = switches[ip_switch].get('ports')
            if ports is None:
                continue
            for port in ports.keys():
                init_mac   = switches[ip_switch]['ports'][port]['init_mac']
                change_mac = switches[ip_switch]['ports'][port]['change_mac']
                func_handler_port(
                    id_switches=id_switches, 
                    ip_switch= ip_switch, 
                    mac_swithces=mac_swithces,
                    ports=ports,
                    port=port, 
                    init_mac=init_mac, 
                    change_mac=change_mac)


    def _get_all_mac_switches(self):
        def _handler(**kwargs):
            mac_swithces = kwargs['mac_swithces']
            all_mac_switches.update(mac_swithces)
        
        all_mac_switches = set()
        self._foreach_switches(None, _handler)
        return all_mac_switches


    def _get_switch_to_switch(self):
        def _handler(**kwargs):
            change_mac   = kwargs['change_mac']
            mac_swithces = kwargs['mac_swithces']
            ip_switch    = kwargs['ip_switch']
            port         = kwargs['port']

            if (len(change_mac & self.all_mac_switches) != 0) and change_mac.isdisjoint(mac_swithces):
                self.switches[ip_switch]['ports'][port]['is_switch'] = True
                if switch_to_switch.get(ip_switch) is None:
                    switch_to_switch[ip_switch]                = {}
                    switch_to_switch[ip_switch]['id_switches'] = self.switches[ip_switch]['id_switches']
                    switch_to_switch[ip_switch]['ports']       = {}
                    switch_to_switch[ip_switch]['mac']         = self.switches[ip_switch]['mac'].copy()

                switch_to_switch[ip_switch]['ports'][port] = self.switches[ip_switch]['ports'][port].copy()

            change_mac.difference_update(final_mac_without_mac_switches)

        final_mac_without_mac_switches = self.get_final_mac()
        final_mac_without_mac_switches.difference_update(self.all_mac_switches)

        switch_to_switch = {}

        self._foreach_switches(_handler)
        
        self._reset_port_change_mac()

        return switch_to_switch

    
    def _reset_port_change_mac(self):
        def _handler(**kwargs):
            ip_switch    = kwargs['ip_switch']
            port         = kwargs['port']
            self.switches[ip_switch]['ports'][port]['change_mac'] = kwargs['init_mac'].copy()

        self._foreach_switches(_handler)


    def get_final_mac(self):
        def _handler(**kwargs):
            change_mac = kwargs['change_mac']
            if len(change_mac) == 1:
                final_mac.update(change_mac)
        
        final_mac = set()
        self._foreach_switches(_handler)

        return final_mac

    
    def clear_all_mac_switches_of_ports(self):
        def _handler(**kwargs):
            change_mac = kwargs['change_mac']
            if len(change_mac) > 1:
                change_mac.difference_update(self.all_mac_switches)
        
        self._foreach_switches(_handler)


    def clear_final_mac_of_ports(self):
        def _handler(**kwargs):
            change_mac = kwargs['change_mac']
            if len(change_mac) > 1:
                change_mac.difference_update(final_mac)

        final_mac = self.get_final_mac()
        self._foreach_switches(_handler)


    def print_count(self):
        def _handler(**kwargs):
            ip_switch    = kwargs['ip_switch']
            port         = kwargs['port']
            mac_swithces = kwargs['mac_swithces']
            init_mac     = kwargs['init_mac']
            change_mac   = kwargs['change_mac']
            print('ip: %15s, port: %3d, count mac_swithces: %3d, count init_mac: %4d, count change_mac: %4d, is_switch: %s' % (
                ip_switch, port, 
                len(mac_swithces), 
                len(init_mac), 
                len(change_mac), 
                self.switches[ip_switch]['ports'][port].get('is_switch', False)))
         
        self._foreach_switches(_handler)


    def get_tree_switch_nodes(self):
        def _handler(**kwargs):
            id_switches  = kwargs['id_switches']
            ip_switch    = kwargs['ip_switch']
            
            nodes.append({
                'id'   : id_switches,
                'label': ip_switch,
            })


        nodes = []
        self._foreach_switches(None, _handler)
        return json.dumps(nodes)

    def get_tree_switch_edges(self):
        def _handler(**kwargs):
            def _find_edge(**kwargs):
                change_mac  = kwargs['change_mac']
                ip_switch    = kwargs['ip_switch']
                id_switch    = kwargs['id_switches']
                mac_swithces = kwargs['mac_swithces']
                port         = kwargs['port']

                self

                if (change_mac.isdisjoint(_subtraction_mac)) :
                    
                    flag = True
                    if len(_change_mac.intersection(mac_swithces)) != 0 :
                        flag = True
                    else:
                        flag = False

                    edges.append({
                        'from'  : _id_switch,
                        'to'    : id_switch,
                        'title' : '%s(%s)-%s(%d)'%(_ip_switch, _port, ip_switch, port),
                    })
                
                    set_mac_final_switches.update(_mac_swithces)
                    if dict_port_final_switches.get(ip_switch) is None:
                        dict_port_final_switches[ip_switch] = set()
                    dict_port_final_switches[ip_switch].add(port)
                    set_ip_final_switches.add(_ip_switch)
                    

            ports = kwargs['ports']
            if len(ports) == 1:
                _ip_switch    = kwargs['ip_switch']
                _id_switch    = kwargs['id_switches']
                _port         = kwargs['port']
                _mac_swithces = kwargs['mac_swithces']
                _change_mac   = kwargs['change_mac']

                _subtraction_mac = self.all_mac_switches - _mac_swithces

                self._foreach_switches(_find_edge, switches=self.switch_to_switch)

        
        def _delete_final_switches():
            def _delete_port():
                for ip in dict_port_final_switches:
                    for port in dict_port_final_switches[ip]:
                        self.switch_to_switch[ip]['ports'].pop(port)


            def _delete_switches():
                for ip in set_ip_final_switches:
                    self.switch_to_switch.pop(ip)


            def _delete_mac_switches(**kwargs):
                change_mac = kwargs['change_mac']
                change_mac = change_mac - set_mac_final_switches

            _delete_port()
            _delete_switches()
            self._foreach_switches(_delete_mac_switches, switches=self.switch_to_switch)

            self.all_mac_switches = self.all_mac_switches - set_mac_final_switches


        edges = []
        set_ip_final_switches = set()
        set_mac_final_switches = set()
        dict_port_final_switches = {}

        self._foreach_switches(_handler, switches=self.switch_to_switch)

        _delete_final_switches()

        if len(set_ip_final_switches) == 0:
            return edges
        
        edges.extend(self.get_tree_switch_edges())

        return edges

    def get_JSON_tree_switch_edges(self):
        return json.dumps(self.get_tree_switch_edges())


if __name__ == "__main__":

    cred = {
        'host'    : '10.4.5.54',
        'user'    : 'pysnmp',
        'passwd'  : '123456',
        'db'      : 'switch_snmp',
        'charset' : 'utf8',
    }

    switch = MonitoringSwitches(cred)

    print(switch.get_tree_switch_edges())

    a = 1
