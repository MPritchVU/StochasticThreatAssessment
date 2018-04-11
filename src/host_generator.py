'''
Created on Feb 15, 2017

@author: Michael Pritchard
'''

import random
import os
import math
import networkx as nx
from nessus_parser import NessusParser
from vuln_profile import VulnProfile
from vuln_dict import VulnDict, VulnEntry
from __builtin__ import list

RESTRICT_GATEWAYS = False
RESTRICT_SERVERS = False

def main():
    report_path = os.path.join('..', "profiles", 'Win7_2014_min.csv')
    parser = NessusParser()
    report = parser.parse_report(report_path)
    vd = VulnDict()
    vp = VulnProfile(report, vd)
    hg = HostGenerator(10, 2, vp, 0.8, 0, 0, 1.0, "BTER")
    for host in hg.host_list:
        print len(host.vulnerabilities)

class HostGenerator(object):
    def __init__(self, num_hosts, connectedness, profiles, network_access_prob, 
                 root_access_prob, user_access_prob, topology):
        self.host_list = []
        for i in range(num_hosts):
            host_name = "host" + str(i)
            host = Host(host_name)
            self.host_list.append(host)

            if topology == "ER":
                for host in self.host_list:
                    neighbors = []
                    for h in self.host_list:
                        if h.name != host.name:
                            if random.random() <= connectedness:
                                neighbors.append(h.name)
                    host.set_neighbors(neighbors)
                    host.set_vuln_profile(profiles[0])
                    
        for host in self.host_list:
            levels = self.determine_access(network_access_prob, 
                                      root_access_prob, user_access_prob)
            host.set_access_levels(levels)

        if topology == "BTER":
            self.generate_bter(num_hosts, connectedness)
            for host in self.host_list:
                host.set_vuln_profile(profiles[0])
                
        if topology == "GEN-1":
            self.generate_gen_1(num_hosts, connectedness)
        
            for host in self.host_list:
                if 'NETWORK' in host.access_levels or host.is_gateway:
                    profile = profiles[2] if random.random() <= 0.336 else profiles[3]
                else:
                    #Proportional ratio of Windows to Linux
                    profile = profiles[0] if random.random() <= 0.7048 else profiles[1]
                host.set_vuln_profile(profile)

    def get_hosts(self):
        return self.host_list

    def determine_access(self, network, root, user):
        levels = []
        if random.random() < network:
            levels.append("NETWORK")
        if random.random() < root:
            levels.append("ROOT")
        if random.random() < user:
            levels.append("USER")
        
        return levels

    def generate_gen_1(self, num_hosts, connectedness):
        degrees = nx.utils.powerlaw_sequence(num_hosts, connectedness)
        self.communities = []
        hosts = [(int(round(degree)), host) for (degree, host) in zip(degrees, self.host_list)]
        self.communities.append([host for host in hosts if host[0] < 2])
        
        # Individual hosts are fully connected
        for entry in self.communities[0]:
            host = entry[1]
            if RESTRICT_SERVERS == True and 'NETWORK' in host.access_levels:
                continue
            for other in self.communities[0]:
                other_host = other[1]
                host.add_neighbor(other_host.name)
        
        degrees = [host for host in hosts if host[0] >= 2]
        degrees.sort()

        # Generate Communities
        while len(degrees) > 0:
            comm_size = degrees[0][0] + 1
            community = []
            while comm_size > 0 and len(degrees) > 0:
                community.append(degrees.pop(0))
                comm_size -= 1
            # Communities are fully connected internally
            for entry in community:
                host = entry[1]
                if 'NETWORK' in host.access_levels:
                    host.access_levels.remove('NETWORK')
                for other in community:
                    other_host = other[1]
                    host.add_neighbor(other_host.name)
                    other_host.add_neighbor(host.name)
            # Assign one host as the gateway
            community[0][1].is_gateway = True
            self.communities.append(community)

        for entry in self.communities[0]:
            host = entry[1]
            for other in self.host_list:
                if other.is_gateway:
                    if 'NETWORK' not in host.access_levels or RESTRICT_SERVERS == False:
                        host.add_neighbor(other.name)
                if not RESTRICT_GATEWAYS:
                    other.add_neighbor(host.name)

        # If the Attacker successfully executes a phishing attack, they can get inside the network via VPN
        vpn_access = False
        for entry in self.communities[0]:
            host = entry[1]
            if 'USER' in host.access_levels:
                vpn_access = True
        
        if vpn_access:
            for entry in self.communities[0]:
                host = entry[1]
                if 'NETWORK' not in host.access_levels:
                    host.add_access_level('NETWORK')
            for host in self.host_list:
                if host.is_gateway:
                    host.add_access_level('NETWORK')
            
    def generate_bter(self, num_hosts, connectedness):
        degrees = nx.utils.powerlaw_sequence(num_hosts, connectedness)
        self.communities = []
        hosts = [(int(round(degree)), host) for (degree, host) in zip(degrees, self.host_list)]
        self.communities.append([host for host in hosts if host[0] < 2])
        degrees = [host for host in hosts if host[0] >= 2]
        degrees.sort()
        d_max = degrees[-1][0]

        while len(degrees) > 0:
            comm_size = degrees[0][0] + 1
            community = []
            while comm_size > 0 and len(degrees) > 0:
                community.append(degrees.pop(0))
                comm_size -= 1
            connect_prob = 1 - math.pow(math.log(community[0][0] + 1) / math.log(d_max + 1), 2)
            for entry in community:
                host = entry[1]
                for other in community:
                    other_host = other[1]
                    if random.random() <= connect_prob:
                        host.add_neighbor(other_host.name)
                        other_host.add_neighbor(host.name)
                entry = (int(entry[0] - connect_prob*(len(community) - 1)), entry[1])
            self.communities.append(community)
        
        excess_degrees = []
        for comm in self.communities:
            for entry in comm:
                if entry[0] > 0:
                    for _ in range(min([entry[0], num_hosts])):
                        excess_degrees.append(entry[1])

        while len(excess_degrees) > 0:
            host_index = random.randint(0, len(excess_degrees) - 1)
            other_index = random.randint(0, len(excess_degrees) - 1)
            host = excess_degrees[host_index]
            other = excess_degrees[other_index]
            if host_index == other_index:
                excess_degrees.remove(host)
                continue
            else:
                host.add_neighbor(other.name)
                other.add_neighbor(host.name)
                excess_degrees.remove(host)
                excess_degrees.remove(other)

class Host(object):
    def __init__(self, name, vuln_profile=None, neighbors=None, access_levels=[], gateway=False):
        self.name = name
        self.access_levels = access_levels
        self.neighbors = neighbors if neighbors is not None else []
        self.is_gateway = gateway
        if vuln_profile is not None:
            self.vulnerabilities = [vuln for vuln in vuln_profile.vuln_list 
                                    if random.random() <= vuln.probabilty]
    
    def set_neighbors(self, neighbors):
        self.neighbors = neighbors
    
    def add_neighbor(self, neighbor):
        if neighbor != self and neighbor not in self.neighbors:
            self.neighbors.append(neighbor)
            
    def add_access_level(self, level):
        self.access_levels.append(level)
    
    def set_access_levels(self, levels):
        self.access_levels = levels

    def set_vuln_profile(self, profile):
        self.vulnerabilities = [vuln for vuln in profile.vuln_list 
                                    if random.random() <= vuln.probabilty]

if __name__ == "__main__":
    main()