from flask import Flask, render_template
from monitoring_switches import MonitoringSwitches

app = Flask(__name__)

cred = {
        'host'    : '10.4.5.54',
        'user'    : 'pysnmp',
        'passwd'  : '123456',
        'db'      : 'switch_snmp',
        'charset' : 'utf8',
    }

    
@app.route('/')
def maps():
    switchs = MonitoringSwitches(cred)

    nodes = switchs.get_tree_switch_nodes()
    edges = switchs.get_JSON_tree_switch_edges()

    return render_template('maps.html', nodes=nodes, edges=edges)