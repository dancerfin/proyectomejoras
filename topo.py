#!/usr/bin/python
from mininet.topo import Topo
from mininet.net import Mininet, Host
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.node import OVSSwitch, Controller, RemoteController
from mininet.link import TCLink
from time import sleep
import random

TEST_TIME = 3600 #seconds
TEST_TYPE = "cli"  # normal attack cli

class CustomTopo(Topo):
    def build(self):
        # Create 5 switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')
        s5 = self.addSwitch('s5')
        
        # Connect switches
        self.addLink(s1, s2, cls=TCLink, bw=10)
        self.addLink(s1, s3, cls=TCLink, bw=10)
        self.addLink(s2, s4, cls=TCLink, bw=10)
        self.addLink(s3, s5, cls=TCLink, bw=10)
        
        # Create and connect hosts for s1 (5 hosts)
        for i in range(1, 6):
            h = self.addHost(f'h{i}', 
                            ip=f'10.1.1.{i}/24', 
                            mac=f"00:00:00:00:00:0{i}", 
                            defaultRoute="via 10.1.1.100")
            self.addLink(h, s1, cls=TCLink, bw=10)
        
        # Create and connect hosts for s2 (2 hosts)
        h6 = self.addHost('h6', ip='10.1.1.6/24', mac="00:00:00:00:00:06", defaultRoute="via 10.1.1.100")
        h7 = self.addHost('h7', ip='10.1.1.7/24', mac="00:00:00:00:00:07", defaultRoute="via 10.1.1.100")
        self.addLink(h6, s2, cls=TCLink, bw=10)
        self.addLink(h7, s2, cls=TCLink, bw=10)
        
        # Create and connect hosts for s3 (2 hosts)
        h8 = self.addHost('h8', ip='10.1.1.8/24', mac="00:00:00:00:00:08", defaultRoute="via 10.1.1.100")
        h9 = self.addHost('h9', ip='10.1.1.9/24', mac="00:00:00:00:00:09", defaultRoute="via 10.1.1.100")
        self.addLink(h8, s3, cls=TCLink, bw=10)
        self.addLink(h9, s3, cls=TCLink, bw=10)
        
        # Create and connect hosts for s4 (2 hosts)
        h10 = self.addHost('h10', ip='10.1.1.10/24', mac="00:00:00:00:00:0a", defaultRoute="via 10.1.1.100")
        h11 = self.addHost('h11', ip='10.1.1.11/24', mac="00:00:00:00:00:0b", defaultRoute="via 10.1.1.100")
        self.addLink(h10, s4, cls=TCLink, bw=10)
        self.addLink(h11, s4, cls=TCLink, bw=10)
        
        # Create and connect hosts for s5 (2 hosts)
        h12 = self.addHost('h12', ip='10.1.1.12/24', mac="00:00:00:00:00:0c", defaultRoute="via 10.1.1.100")
        h13 = self.addHost('h13', ip='10.1.1.13/24', mac="00:00:00:00:00:0d", defaultRoute="via 10.1.1.100")
        self.addLink(h12, s5, cls=TCLink, bw=10)
        self.addLink(h13, s5, cls=TCLink, bw=10)

if __name__ == '__main__':
    setLogLevel('info')
    topo = CustomTopo()
    c1 = RemoteController('c1', ip='127.0.0.1')
    net = Mininet(topo=topo, controller=c1)
    net.start()

    if TEST_TYPE == "normal":
        print("Generating NORMAL Traffic.......")
        # Start servers in multiple hosts (h5, h7, h9, h11, h13)
        for i in [5, 7, 9, 11, 13]:
            h = net.get(f'h{i}')
            h.cmd("iperf -s &")
            h.cmd("iperf -u -s &")
        
        sleep(5)
        
        # Start normal traffic from other hosts
        for i in range(1, 14):
            if i not in [5, 7, 9, 11, 13]:  # Skip server hosts
                h = net.get(f'h{i}')
                h.cmd("bash normal.sh &")
                
                # Randomly assign some hosts to generate iperf traffic
                if random.random() > 0.5:
                    target = random.choice([5, 7, 9, 11, 13])
                    h.cmd(f"iperf -u -b 2m -c 10.1.1.{target} -t {TEST_TIME} &")
                    h.cmd(f"iperf -c 10.1.1.{target} -t {TEST_TIME} &")
        
        sleep(TEST_TIME)
        net.stop()

    elif TEST_TYPE == "attack":
        print("Generating ATTACK Traffic.......")
        # Select some hosts to be attackers (e.g., h1, h2, h6, h8)
        attackers = [1, 2, 6, 8]
        for i in attackers:
            h = net.get(f'h{i}')
            h.cmd("bash attack.sh &")
        
        # Also have some normal traffic
        for i in range(1, 14):
            if i not in attackers:
                h = net.get(f'h{i}')
                h.cmd("bash normal.sh &")
        
        sleep(TEST_TIME)
        net.stop()

    else:
        print("Starting CLI mode...")
        # Start some servers for testing
        for i in [5, 7, 9, 11, 13]:
            h = net.get(f'h{i}')
            h.cmd("iperf -s &")
            h.cmd("iperf -u -s &")
        
        # Start normal traffic in background
        for i in range(1, 14):
            if i not in [5, 7, 9, 11, 13]:
                h = net.get(f'h{i}')
                h.cmd("bash normal.sh &")
        
        CLI(net)
        net.stop()