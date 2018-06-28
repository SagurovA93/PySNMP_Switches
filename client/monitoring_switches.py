import json
import MySQLdb


class MonitoringSwitches:
    
    def __init__(self, cred_db):
        
        self.cred_db  = cred_db
        self.switches = {}

        db = MySQLdb.connect(**self.cred_db)
        cursor = db.cursor()
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
                self.switches[ip] = {}
                self.switches[ip]['ports'] = {}
            if self.switches[ip]['ports'].get(port_number) is None:
                self.switches[ip]['ports'][port_number] = set()
            
            self.switches[ip]['ports'][port_number].add(mac)
            self.switches[ip]['id_switches'] = id_switches

        db.close()

    def _foreach_switches(self, func_handler):
        for ip_switch in self.switches.keys():
            id_switches = self.switches[ip_switch]['id_switches']
            for port in self.switches[ip_switch]['ports'].keys():
                mac = self.switches[ip_switch]['ports'][port]
                func_handler(id_switches=id_switches, port=port, mac=mac)

    def get_final_mac(self):
        def _handler(**kwargs):
            mac = kwargs['mac']
            if len(mac) == 1:
                final_mac.update(mac)
        
        final_mac = set()
        self._foreach_switches(_handler)
        return final_mac

    def clear_final_mac_of_ports(self):
        def _handler(**kwargs):
            mac = kwargs['mac']
            if len(mac) > 1:
                mac.difference_update(final_mac)

        final_mac = self.get_final_mac()
        self._foreach_switches(_handler)
        


if __name__ == "__main__":

    cred = {
        'host'    : '10.4.5.54',
        'user'    : 'pysnmp',
        'passwd'  : '123456',
        'db'      : 'switch_snmp',
        'charset' : 'utf8',
    }

    switch = MonitoringSwitches(cred)
    print(len(switch.get_final_mac()))


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
