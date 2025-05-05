from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, arp, ipv4
from ryu.lib import hub
import csv
from datetime import datetime
import statistics
from ml import MachineLearningAlgo

# Configuración
APP_TYPE = 0  # 0: datacollection, 1: ddos detection
PREVENTION = 0
TEST_TYPE = 0
INTERVAL = 5

# Estructuras globales
gflows = {}
iteration = {}
old_ssip_len = {}
prev_flow_count = {}
flow_cookie = {}
BLOCKED_PORTS = {}
keystore = {}

def get_iteration(dpid):
    global iteration
    iteration.setdefault(dpid, 0)
    return iteration[dpid]

def set_iteration(dpid, count):
    global iteration
    iteration[dpid] = count

def calculate_value(key, val):
    key = str(key).replace(".", "_")
    if key in keystore:
        oldval = keystore[key]
        cval = (val - oldval) 
        keystore[key] = val
        return cval
    else:
        keystore[key] = val
        return 0

class DDoSML(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DDoSML, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.arp_ip_to_port = {}
        self.datapaths = {}
        self.mitigation = 0
        self.mlobj = MachineLearningAlgo() if APP_TYPE == 1 else None
        self.flow_thread = hub.spawn(self._flow_monitor)

    def _flow_monitor(self):
        hub.sleep(INTERVAL * 2)
        while True:
            for dp in self.datapaths.values():
                self.request_flow_metrics(dp)
            hub.sleep(INTERVAL)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        
        self.datapaths[dpid] = datapath
        self.mac_to_port[dpid] = {}
        self.arp_ip_to_port[dpid] = {}
        BLOCKED_PORTS[dpid] = []

        # Flujos básicos
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath, 0, match, actions, get_flow_number(dpid))

        # Flujo ARP
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
        self.add_flow(datapath, 10, match, actions, get_flow_number(dpid))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        if not eth or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # Inicializar estructuras
        self.mac_to_port.setdefault(dpid, {})
        self.arp_ip_to_port.setdefault(dpid, {})
        self.arp_ip_to_port[dpid].setdefault(in_port, [])
        BLOCKED_PORTS.setdefault(dpid, [])

        # Aprender MAC
        self.mac_to_port[dpid][eth.src] = in_port
        out_port = self.mac_to_port[dpid].get(eth.dst, ofproto.OFPP_FLOOD)

        # Manejar ARP
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            arp_pkt = pkt.get_protocol(arp.arp)
            if arp_pkt and arp_pkt.src_ip not in self.arp_ip_to_port[dpid][in_port]:
                self.arp_ip_to_port[dpid][in_port].append(arp_pkt.src_ip)

        # Instalar flujo
        if out_port != ofproto.OFPP_FLOOD:
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip_pkt = pkt.get_protocol(ipv4.ipv4)
                if ip_pkt:
                    match = parser.OFPMatch(
                        in_port=in_port,
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=ip_pkt.src,
                        ipv4_dst=ip_pkt.dst)
                    
                    actions = [parser.OFPActionOutput(out_port)]
                    self.add_flow(datapath, 1, match, actions, get_flow_number(dpid))

        # Enviar paquete
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None)
        datapath.send_msg(out)

    # ... (resto de métodos existentes sin cambios)

if __name__ == '__main__':
    from ryu.cmd import manager
    manager.main()