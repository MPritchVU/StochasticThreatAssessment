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

def generate_er(host_list, connectedness):
    for host in host_list:
        for other in host_list:
            if other.name != host.name:
                if random.random() <= connectedness:
                    host.add_outgoing(other.name)
                    other.add_incoming(host.name)

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

def generate_gen_1(host_list, connectedness):
    # Generate a sequence of degree values to seed the topology structure
    degrees = nx.utils.powerlaw_sequence(len(host_list), connectedness)

    # Assign sequence values to each host
    hosts = [(int(round(degree)), host) for (degree, host) in zip(degrees, host_list)]
    
    # Gather all singleton hosts (sequence value == 1)
    communities = [[host for host in hosts if host[0] < 2]]
    
    # Non-server singleton hosts are fully connected
    for (_, host) in communities[0]:
        host.type = 'SINGLETON' if 'NETWORK' not in host.get_access_levels() else 'SERVER'
        # If we're restricting servers, they don't get outgoing connections to other hosts
        if RESTRICT_SERVERS and host.get_type() == 'SERVER':
            continue
        for (_, other) in communities[0]:
            host.add_outgoing(other.name)
            other.add_incoming(host.name)

    # Sort the remaining hosts by their sequence value
    degrees = [host for host in hosts if host[0] >= 2]
    degrees.sort()

    # Generate Communities
    while len(degrees) > 0:
        # Each community is of size n + 1, where n is lowest sequence value remaining
        size = degrees[0][0] + 1
        community = []

        while size > 0 and len(degrees) > 0:
            community.append(degrees.pop(0))
            size -= 1

        # Communities are fully connected internally
        for (_, host) in community:
            for (_, other) in community:
                host.add_outgoing(other.name)
                other.add_incoming(host.name)

            # Internal devices cannot be accessed from outside the network
            if 'NETWORK' in host.access_levels:
                host.access_levels.remove('NETWORK')

        # Assign one host as the gateway
        community[0][1].set_type = 'GATEWAY'
        communities.append(community)

    for (_, host) in communities[0]:
        for other in host_list:
            if other.get_type() == 'GATEWAY':
                if host.type == 'SINGLETON' or RESTRICT_SERVERS == False:
                    host.add_outgoing(other.name)
                    other.add_incoming(host.name)
            if not RESTRICT_GATEWAYS:
                other.add_outgoing(host.name)
                host.add_incoming(other.name)

TOPOLOGIES = {'ER': generate_er, 'BTER': generate_bter, 'GEN-1': generate_gen_1}

class Host(object):
    def __init__(self, name, type="GENERIC"):
        self.name = name
        self.type = type
        self.vuln_profile = None
        self.incoming = []
        self.outgoing = []
        self.access_levels = []

    def set_type(self, type):
        self.type = type

    def set_vuln_profile(self, vuln_profile):
        self.vuln_profile = vuln_profile

    def set_incoming(self, hosts):
        self.incoming = hosts

    def set_outgoing(self, hosts):
        self.outgoing = hosts

    def add_incoming(self, host):
        if host != self and host not in self.incoming:
            self.incoming.append(host)

    def add_outgoing(self, host):
        if host != self and host not in self.outgoing:
            self.outgoing.append(host)

    def add_access_level(self, level):
        self.access_levels.append(level)

    def remove_access_level(self, level):
        if level in self.access_levels:
            self.access_levels.remove(level)
    
    def remove_outgoing(self, other):
        self.outgoing.remove(other)

    def get_type(self):
        return self.type

    def get_incoming(self):
        return self.incoming

    def get_outgoing(self):
        return [self.name + '->' + other for other in self.outgoing]

    def get_edge_count(self):
        return len(self.outgoing) + len(self.incoming)

    def get_access_levels(self):
        return self.access_levels

    def generate_vulnerabilities(self):
        if self.vuln_profile is None:
            raise ValueError(''.join([host.name, ' does not have an assigned vulnerability profile!']))

        self.vulnerabilities = [vuln for vuln in self.vuln_profile.vuln_list 
                                    if random.random() <= vuln.probabilty]

    def generate_access_levels(self, access_probs, fix_network=True):
        for (level, prob) in access_probs.items():
            if level == 'NETWORK' and fix_network:
                continue
            if random.random() <= prob:
                self.access_levels.append(level)

class HostGenerator(object):
    def __init__(self, num_hosts, topology, connectedness, access_probs, profiles):
        self.topology = topology
        self.host_list = [Host('host-' + str(i)) for i in range(num_hosts)]
        self.access_probs = access_probs
        self.generate_access_levels(False, False)
        self.assign_profiles(profiles)
        self.generate_vulnerabilities()
        TOPOLOGIES[topology](self.host_list, connectedness)
        
        if self.topology == 'GEN-1':
            self.generate_access_levels()

    def get_hosts(self):
        return self.host_list
    
    def get_host_dict(self):
        return {host.name: host for host in self.host_list}

    def assign_profiles(self, profiles):
        for host in self.host_list:
            profile_list = profiles[host.type]
            val = random.random()
            cum_prob = 0
            for (prob, profile) in profile_list:
                cum_prob += prob
                if val <= cum_prob:
                    host.set_vuln_profile(profile)
                    break

    def generate_access_levels(self, fix_network=True, post_init=True):
        for host in self.host_list:
            host.generate_access_levels(self.access_probs, fix_network)
        
        if self.topology == 'GEN-1' and post_init:
            # If the Attacker successfully executes a phishing attack, they can get inside the network via VPN
            vpn_access = False
            for host in [host for host in self.host_list if host.get_type() == 'SINGLETON']:
                if 'USER' in host.get_access_levels():
                    vpn_access = True
                    break

            if vpn_access:
                for host in [host for host in self.host_list if host.get_type() in ['GATEWAY', 'SINGLETON']]:
                    host.add_access_level('NETWORK')
            else:
                for host in [host for host in self.host_list if host.get_type() in ['GATEWAY', 'SINGLETON']]:
                    host.remove_access_level('NETWORK')

    def generate_vulnerabilities(self):
        for host in self.host_list:
            host.generate_vulnerabilities()


