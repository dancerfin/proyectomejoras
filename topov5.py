#!/usr/bin/python
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.node import OVSSwitch, RemoteController
from mininet.link import TCLink
from time import sleep, time
import random
import sys
import os

# Configuración global
TEST_DURATION = 300
TRAFFIC_TYPES = ["normal", "attack", "mixed", "cli"]
DEFAULT_TYPE = "mixed"
SERVER_PORTS = [5001, 5002, 80]

class AdvancedTopo(Topo):
    def __init__(self, **opts):
        self.host_ips = {}
        self.server_hosts = [5, 7, 9, 11, 13]
        Topo.__init__(self, **opts)

    def build(self):
        info('*** Creando topología\n')
        
        # Crear switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')
        s5 = self.addSwitch('s5')
        
        # Conectar switches
        self.addLink(s1, s2, cls=TCLink, bw=20, delay='1ms')
        self.addLink(s1, s3, cls=TCLink, bw=20, delay='1ms')
        self.addLink(s2, s4, cls=TCLink, bw=15, delay='2ms')
        self.addLink(s3, s5, cls=TCLink, bw=15, delay='2ms')
        
        # Configurar hosts
        for i in range(1, 14):
            ip = f'10.1.1.{i}'
            h = self.addHost(f'h{i}', ip=ip+'/24',
                           mac=f"00:00:00:00:00:{i:02x}",
                           defaultRoute="via 10.1.1.254")
            
            if i <= 5:
                self.addLink(h, s1, cls=TCLink, bw=10)
            elif i <= 7:
                self.addLink(h, s2, cls=TCLink, bw=10)
            elif i <= 9:
                self.addLink(h, s3, cls=TCLink, bw=10)
            elif i <= 11:
                self.addLink(h, s4, cls=TCLink, bw=10)
            else:
                self.addLink(h, s5, cls=TCLink, bw=10)
            
            self.host_ips[f'h{i}'] = ip

def start_services(net, server_hosts):
    info('*** Iniciando servicios en servidores\n')
    for host_num in server_hosts:
        h = net.get(f'h{host_num}')
        h.cmd(f'iperf -s -p {SERVER_PORTS[0]} > iperf_tcp_{host_num}.log &')
        h.cmd(f'iperf -u -s -p {SERVER_PORTS[1]} > iperf_udp_{host_num}.log &')
        h.cmd(f'python -m SimpleHTTPServer {SERVER_PORTS[2]} > web_{host_num}.log 2>&1 &')
        info(f'  h{host_num} ({h.IP()}): Servicios iniciados\n')

def start_normal_traffic(net, exclude_servers):
    info('*** Iniciando tráfico normal\n')
    for host in net.hosts:
        host_num = int(host.name[1:])
        if host_num not in exclude_servers:
            host.cmd(f'bash normal.sh > normal_{host_num}.log &')
            if random.random() > 0.3:
                target = random.choice(exclude_servers)
                host.cmd(f'iperf -c 10.1.1.{target} -p {SERVER_PORTS[0]} -t {TEST_DURATION//2} > iperf_tcp_{host_num}.log &')
                host.cmd(f'iperf -u -b 1m -c 10.1.1.{target} -p {SERVER_PORTS[1]} -t {TEST_DURATION//2} > iperf_udp_{host_num}.log &')

def start_attack_traffic(net, attackers):
    info('*** Iniciando tráfico malicioso\n')
    for attacker_num in attackers:
        h = net.get(f'h{attacker_num}')
        h.cmd(f'bash attack.sh > attack_{attacker_num}.log &')
        info(f'  h{attacker_num} ({h.IP()}): Iniciando ataques\n')

def monitor_traffic(net, duration):
    info(f'*** Ejecutando prueba por {duration} segundos\n')
    for remaining in range(duration, 0, -10):
        info(f'  Tiempo restante: {remaining} segundos\n')
        sleep(10)
    info('*** Prueba completada\n')

def cleanup(net):
    info('*** Limpiando\n')
    for host in net.hosts:
        host.cmd('killall -9 iperf python bash hping3 curl 2>/dev/null')

def main():
    test_type = DEFAULT_TYPE
    if len(sys.argv) > 1 and sys.argv[1] in TRAFFIC_TYPES:
        test_type = sys.argv[1]
    
    duration = TEST_DURATION
    if len(sys.argv) > 2 and sys.argv[2].isdigit():
        duration = int(sys.argv[2])
    
    setLogLevel('info')
    
    topo = AdvancedTopo()
    c1 = RemoteController('c1', ip='192.168.1.47')
    net = Mininet(topo=topo, controller=c1, link=TCLink)
    net.start()
    
    try:
        server_hosts = topo.server_hosts
        attackers = [1, 2, 6, 8]
        
        start_services(net, server_hosts)
        start_normal_traffic(net, server_hosts)
        
        if test_type == "attack":
            start_attack_traffic(net, attackers)
        elif test_type == "mixed":
            start_attack_traffic(net, attackers[:2])
        elif test_type == "cli":
            info('*** Modo CLI activado\n')
            CLI(net)
            return
        
        monitor_traffic(net, duration)
    finally:
        cleanup(net)
        net.stop()

if __name__ == '__main__':
    main()