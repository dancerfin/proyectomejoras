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
TEST_DURATION = 600  # Duración default de pruebas (segundos)
TRAFFIC_TYPES = ["normal", "attack", "mixed", "cli"]
DEFAULT_TYPE = "mixed"  # Modo por defecto
SERVER_PORTS = [5001, 5002, 80]  # Puertos para servicios

class AdvancedTopo(Topo):
    def __init__(self, **opts):
        # Inicializar atributos antes de llamar al constructor padre
        self.host_ips = {}  # Diccionario para guardar IPs de hosts
        self.server_hosts = [5, 7, 9, 11, 13]  # Hosts servidores
        
        # Llamar al constructor de la clase padre
        Topo.__init__(self, **opts)

    def build(self):
        """Construye la topología de 5 switches y 13 hosts"""
        info('*** Creando topología\n')
        
        # Crear 5 switches interconectados
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')
        s5 = self.addSwitch('s5')
        
        # Conectar switches (topología en árbol)
        self.addLink(s1, s2, cls=TCLink, bw=10, delay='2ms')
        self.addLink(s1, s3, cls=TCLink, bw=10, delay='2ms')
        self.addLink(s2, s4, cls=TCLink, bw=8, delay='3ms')
        self.addLink(s3, s5, cls=TCLink, bw=8, delay='3ms')
        
        # Agregar hosts al switch central s1 (5 hosts)
        for i in range(1, 6):
            ip = f'10.1.1.{i}'
            h = self.addHost(f'h{i}', ip=ip+'/24', 
                            mac=f"00:00:00:00:00:{i:02x}",
                            defaultRoute="via 10.1.1.100")
            self.addLink(h, s1, cls=TCLink, bw=5+random.random()*5)
            self.host_ips[f'h{i}'] = ip
        
        # Agregar hosts a los switches restantes (2 hosts por switch)
        host_counter = 6
        for sw in [s2, s3, s4, s5]:
            for _ in range(2):
                ip = f'10.1.1.{host_counter}'
                h = self.addHost(f'h{host_counter}', ip=ip+'/24',
                                mac=f"00:00:00:00:00:{host_counter:02x}",
                                defaultRoute="via 10.1.1.100")
                self.addLink(h, sw, cls=TCLink, bw=5+random.random()*5)
                self.host_ips[f'h{host_counter}'] = ip
                host_counter += 1

def start_services(net, server_hosts):
    """Inicia servicios en los hosts servidores"""
    info('*** Iniciando servicios en servidores\n')
    for host_num in server_hosts:
        h = net.get(f'h{host_num}')
        
        # Servidor iperf TCP
        h.cmd(f'iperf -s -p {SERVER_PORTS[0]} > iperf_tcp_{host_num}.log &')
        
        # Servidor iperf UDP
        h.cmd(f'iperf -u -s -p {SERVER_PORTS[1]} > iperf_udp_{host_num}.log &')
        
        # Servidor web simple
        h.cmd(f'python -m SimpleHTTPServer {SERVER_PORTS[2]} > web_{host_num}.log 2>&1 &')
        
        info(f'  h{host_num} ({h.IP()}): Servicios iniciados\n')

def start_normal_traffic(net, exclude_servers):
    """Inicia tráfico normal en los hosts clientes"""
    info('*** Iniciando tráfico normal\n')
    for host in net.hosts:
        host_num = int(host.name[1:])
        if host_num not in exclude_servers:
            # Tráfico de fondo
            host.cmd(f'bash normal.sh > normal_{host_num}.log &')
            
            # Conexiones iperf ocasionales
            if random.random() > 0.3:
                target = random.choice(exclude_servers)
                host.cmd(
                    f'iperf -c 10.1.1.{target} -p {SERVER_PORTS[0]} '
                    f'-t {TEST_DURATION//2} > iperf_tcp_{host_num}.log &'
                )
                host.cmd(
                    f'iperf -u -b 1m -c 10.1.1.{target} -p {SERVER_PORTS[1]} '
                    f'-t {TEST_DURATION//2} > iperf_udp_{host_num}.log &'
                )

def start_attack_traffic(net, attackers):
    """Inicia tráfico de ataque desde hosts específicos"""
    info('*** Iniciando tráfico malicioso\n')
    for attacker_num in attackers:
        h = net.get(f'h{attacker_num}')
        h.cmd(f'bash attack.sh > attack_{attacker_num}.log &')
        info(f'  h{attacker_num} ({h.IP()}): Iniciando ataques\n')

def monitor_traffic(net, duration):
    """Monitoriza el tráfico durante la prueba"""
    info(f'*** Ejecutando prueba por {duration} segundos\n')
    for remaining in range(duration, 0, -10):
        info(f'  Tiempo restante: {remaining} segundos\n')
        sleep(10)
    info('*** Prueba completada\n')

def cleanup(net):
    """Limpia procesos y archivos temporales"""
    info('*** Limpiando\n')
    for host in net.hosts:
        host.cmd('killall -9 iperf python bash hping3 curl 2>/dev/null')

def main():
    # Configurar parámetros
    test_type = DEFAULT_TYPE
    if len(sys.argv) > 1 and sys.argv[1] in TRAFFIC_TYPES:
        test_type = sys.argv[1]
    
    duration = TEST_DURATION
    if len(sys.argv) > 2 and sys.argv[2].isdigit():
        duration = int(sys.argv[2])
    
    setLogLevel('info')
    
    # Crear red
    topo = AdvancedTopo()
    c1 = RemoteController('c1', ip='127.0.0.1')
    net = Mininet(topo=topo, controller=c1, link=TCLink)
    net.start()
    
    try:
        # Configurar hosts
        server_hosts = topo.server_hosts
        attackers = [1, 2, 6, 8]  # Hosts que realizarán ataques
        
        # Iniciar servicios en servidores
        start_services(net, server_hosts)
        
        # Iniciar tráfico normal en clientes
        start_normal_traffic(net, server_hosts)
        
        # Configurar según tipo de prueba
        if test_type == "attack":
            start_attack_traffic(net, attackers)
        elif test_type == "mixed":
            # Iniciar solo algunos atacantes
            start_attack_traffic(net, attackers[:2])
        elif test_type == "cli":
            info('*** Modo CLI activado\n')
            CLI(net)
            return
        
        # Ejecutar prueba por el tiempo especificado
        monitor_traffic(net, duration)
        
    finally:
        cleanup(net)
        net.stop()

if __name__ == '__main__':
    main()