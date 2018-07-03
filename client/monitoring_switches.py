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


    def _db_switches_port(self, cursor):
        
        query_all_switches = '''
            SELECT switches.id_switches, switches.ip, ports.port_number, FDB_tables.mac_address
            FROM switches
            INNER JOIN ports using(id_switches)
            INNER JOIN FDB_tables using(id_ports)
            INNER JOIN requests using(id_requests)
            WHERE requests.DATE = (SELECT MAX(requests.DATE) FROM requests)
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
            WHERE requests.DATE = (SELECT MAX(requests.DATE) FROM requests);
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


    def get_final_mac(self):
        def _handler(**kwargs):
            change_mac = kwargs['change_mac']
            if len(change_mac) == 1:
                final_mac.update(change_mac)
        
        final_mac = set()
        self._foreach_switches(_handler)

        #final_mac.difference_update(self.all_mac_switches)
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
            print('ip: %15s, port: %3d, count mac_swithces: %3d, count init_mac: %4d, count change_mac: %4d' % (
                ip_switch, port, len(mac_swithces), len(init_mac), len(change_mac)))
         
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
            def _handler_port(**kwargs):
                id_switches = kwargs['id_switches']
                ip_switch   = kwargs['ip_switch']
                port        = kwargs['port']
                change_mac  = kwargs['change_mac']
                if (_id_switches == id_switches):
                    return
                if len(change_mac & _mac_swithces) != 0:
                    edges.append({
                        'from'  : _id_switches,
                        'to'    : id_switches,
                        'title' : '%s-%s(%d)'%(_ip_switch, ip_switch, port),
                    })

            _id_switches  = kwargs['id_switches']
            _ip_switch    = kwargs['ip_switch']
            _mac_swithces = kwargs['mac_swithces']
            if _ip_switch == '10.4.0.209':   
                self._foreach_switches(_handler_port)

        edges = []
        self._foreach_switches(None, _handler)
        return json.dumps(edges)


    def _get_switch_ports_to_switch(self):
        def _handler(**kwargs):
            change_mac = kwargs['change_mac']
            ip_switch  = kwargs['ip_switch']
            port       = kwargs['port']

            if len(change_mac & self.all_mac_switches) != 0:
                self.switches[ip_switch]['ports'][port]['is_switch'] = True
                switch_ports_to_switch[ip_switch] = self.switches[ip_switch]

            change_mac.difference_update(final_mac_without_mac_switches)

        final_mac_without_mac_switches = self.get_final_mac()
        final_mac_without_mac_switches.difference_update(self.all_mac_switches)

        switch_ports_to_switch = {}

        self._foreach_switches(_handler)

        return switch_ports_to_switch

    

    def test_print(self):
        def _handler(**kwargs):

            ip_switch    = kwargs['ip_switch']
            port         = kwargs['port']
            mac_swithces = kwargs['mac_swithces']
            init_mac     = kwargs['init_mac']
            change_mac   = kwargs['change_mac']

            if len(change_mac) == 0:
                return

            print('ip: %15s, port: %3d, count mac_swithces: %3d, count init_mac: %4d, count change_mac: %4d, is_switch: %s' % (
                ip_switch, port, 
                len(mac_swithces), 
                len(init_mac), 
                len(change_mac), 
                self.switches[ip_switch]['ports'][port].get('is_switch', False)))
         
        self._foreach_switches(_handler, switches=self.switch_ports_to_switch)


if __name__ == "__main__":

    cred = {
        'host'    : '10.4.5.54',
        'user'    : 'pysnmp',
        'passwd'  : '123456',
        'db'      : 'switch_snmp',
        'charset' : 'utf8',
    }

    switch = MonitoringSwitches(cred)

    switch.switch_ports_to_switch = switch._get_switch_ports_to_switch()
    switch.test_print()

    a = 1
    
    #switch.clear_final_mac_of_ports()
    #switch.clear_all_mac_switches_of_ports()
    
    #print(switch.get_tree_switch_nodes())
    #print(switch.get_tree_switch_edges())

    #switch.print_count()


def tree_swicthes(switches):
    def find_mac(switches, mac1):
        res = []
        
        for ip in switches.keys():
            id = switches[ip]['id']
            for port, mac in switches[ip].items():
                if port == 'id':
                    continue
                if mac1 in mac:
                    res.append({'id': id, 'port': port})
        return res

    nodes = []
    edges = []

    for ip in switches.keys():
        for port, mac in switches[ip].items():
            if port == 'id':
                continue
            if len(mac) == 1:
                nodes.append({'label': list(mac)[0]})

    for ip in switches.keys():
        nodes.append({'id': switches[ip]['id'], 'label': ip})

    id_edges = 0
    for ip in switches.keys():
        id = switches[ip]['id']
        for port, mac in switches[ip].items():
            if port == 'id':
                continue
            tmp_edges = []
            if len(mac) > 2:
                continue
            for m in mac:
                tmp_edges.extend(find_mac(switches, m))

            for tmp_edge in tmp_edges:
                id_edges += 1
                edges.append({'id': id_edges, 'from': id ,'to': tmp_edge['id'], 'title':port})
            
    return (json.dumps(nodes), json.dumps(edges))
