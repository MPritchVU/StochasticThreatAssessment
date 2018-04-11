###############################################################################
## Description
###############################################################################

# generates a domain file and an init file for an edge
# the domain file is generated using a form of encoded pddl
# since parsing actual pddl might be more tedious

###############################################################################
## Setup
###############################################################################

import os
import sys
import time
import random
from host_generator import HostGenerator
from nessus_parser import NessusParser
from vuln_profile import VulnProfile
from vuln_dict import VulnDict, VulnEntry

FILE_DIR = os.path.abspath(os.path.dirname(__file__))
WIN_DESK_PATH = os.path.join(FILE_DIR, '..', 'profiles', 'Win7_2014_min.csv')
LIN_DESK_PATH = os.path.join(FILE_DIR, '..', 'profiles', 'Ubuntu_2014.csv')
WIN_SERV_PATH = os.path.join(FILE_DIR, '..', 'profiles', 'WinServer2012.csv')
LIN_SERV_PATH = os.path.join(FILE_DIR, '..', 'profiles', 'Ubuntu_Server_2014.csv')

# HOST_NUM = int(sys.argv[1])
# CONNECTEDNESS = float(sys.argv[2])
# NETWORK_ACCESS_PROB = float(sys.argv[3])
# ROOT_ACCESS_PROB = float(sys.argv[4])
# USER_ACCESS_PROB = float(sys.argv[5])
# EXPLOIT_SUCCESS_MOD = float(sys.argv[6])

def setup(HOST_NUM, CONNECTEDNESS, NETWORK_ACCESS_PROB, ROOT_ACCESS_PROB, USER_ACCESS_PROB, TOPOLOGY, vuln_dict, MARKER):

    DOMAIN_FILE = os.path.join(FILE_DIR, 'domain' + MARKER)
    PROBLEM_FILE = os.path.join(FILE_DIR, 'problem' + MARKER)
    ###############################################################################
    ## Helper Functions
    ###############################################################################
    
    def format_pddl_type(pddl_type, objects):
        """
        Formats pddl variables where pddl_type is a string and objects is 
        an iterable containing strings that are pddl variables of type pddl_type
        """
        return pddl_type + '|' + ','.join(objects)
    
    def parse_profiles(profile_paths):
        parser = NessusParser()
        profiles = []
        for path in profile_paths:
            report = parser.parse_report(path)
            profile = VulnProfile(report, vuln_dict)
            profile.exclude_year(['2017', '2016', '2015'])
            profile.filter_zero_day()
            profiles.append(profile)
        
        return profiles
    
    ###############################################################################
    ## Open files/Initialize Objects
    ###############################################################################
    time.sleep(0.1)
    domain = open(DOMAIN_FILE, 'w')
    problem = open(PROBLEM_FILE, 'w')
    profiles = parse_profiles([WIN_DESK_PATH, LIN_DESK_PATH, WIN_SERV_PATH, LIN_SERV_PATH])
    host_gen = HostGenerator(HOST_NUM, CONNECTEDNESS, profiles, NETWORK_ACCESS_PROB,
                             ROOT_ACCESS_PROB, USER_ACCESS_PROB, TOPOLOGY)
    
    ###############################################################################
    ## Domain - Types
    ##   The types begin with the label 'types' followed by a colon. 
    ##   A comma-separated list of types follows the label.
    ##   E.g. types:type1,type2,type3
    ###############################################################################
    
    print >> domain, 'types:' + ','.join(['host', 'vulnerability', 'file']) 
    
    ###############################################################################
    ## Domain - Constants
    ##   The constants begin with the label 'constants' followed by a colon. 
    ##   The constants are specified as follows:
    ##     For a given type of constant, the type is specified by its name, 
    ##     followed by a vertical bar and a comma-separated list of constants of
    ##     that type.
    ##     Each type of constant is then joined by a colon.
    ##     E.g. constants:type1|const1,const2:type2|const3,const4
    ###############################################################################
    
    hosts = host_gen.get_hosts()
    hosts_string = format_pddl_type('host', [host.name for host in hosts])
    files = format_pddl_type('file', ['File'])
    print >> domain, 'constants:' + ':'.join((hosts_string, files))
    
    ###############################################################################
    ## Domain - Predicates
    ##   The predicates begin with the label 'predicates' followed by a colon. 
    ##   The predicates are specified as follows:
    ##     Each predicate consists of a semicolon-separated list of the predicate 
    ##     name followed by its parameters. The parameters are specified in the 
    ##     same way as the constants, by its type, followed by a vertical bar, 
    ##     followed by a comma-separated list of parameters of that type.
    ##     Each predicate is then joined by a colon.
    ##     E.g. predicates:p1;type1|param1;type2|param2:p2;type3|param3,param4
    ###############################################################################
    
    p_1 = ';'.join(('connected', 
                            format_pddl_type('host', ['?lh', '?rh'])))
    p_2 = ';'.join(('has_vulnerability', 
                            format_pddl_type('host', ['?h']), 
                            format_pddl_type('vulnerability', ['?v'])))
    p_3 = ';'.join(('network_access',
                            format_pddl_type('host', ['?h'])))
    p_4 = ';'.join(('adjacent_access',
                            format_pddl_type('host', ['?h'])))
    p_5 = ';'.join(('local_access',
                            format_pddl_type('host', ['?h'])))
    p_6 = ';'.join(('user_access',
                            format_pddl_type('host', ['?h'])))
    p_7 = ';'.join(('root_access',
                            format_pddl_type('host', ['?h'])))
    p_8 = ';'.join(('has_file',
                            format_pddl_type('host', ['?h']),
                            format_pddl_type('file', ['?f'])))
    p_9 = ';'.join(('read_access',
                            format_pddl_type('host', ['?h'])))
    p_10 = ';'.join(('compromised',
                            format_pddl_type('host', ['?'])))
    p_11 = ';'.join(('accessed',
                            format_pddl_type('file', ['?f'])))
    
    print >> domain, 'predicates:' + ':'.join((p_1, p_2, p_3, p_4, p_5, 
                                               p_6, p_7, p_8, p_9, p_10, p_11))
    
    ###############################################################################
    ## Domain - Actions
    ##   The actions begin with the label 'action' followed by a colon. 
    ##   The actions are specified as follows:
    ##     The parameters for an action are specified in the same way as the
    ##     parameters for predicates, as a semicolon-delimited list of typed 
    ##     parameters, where the type and parameter are joined by a vertical bar
    ##     and each parameter is joined by a comma.
    ##     The preconditions for an action are a semicolon-delimited list of 
    ##     predicates, where each predicate is a comma-separated list of the 
    ##     predicate name and its parameters.
    ##     The effects for an action are a semicolon-delimited list of 
    ##     predicates, where each predicate is a comma-separated list of the 
    ##     predicate name and its parameters.
    ##     The entire action is defined as a colon-separated list of 
    ##     action, action name, parameters, preconditions, and effects.
    ##     E.g. action:name:type1|param1;type2|param2:pred1,param2:pred2,param1
    ###############################################################################
    
    def action_exploit(vuln):
        parameters = format_pddl_type('host', ['?h'])
        preconditions = []
        preconditions.append(','.join(('has_vulnerability', '?h', vuln.name)))
        if vuln.min_av == "LOCAL":
            preconditions.append(','.join(('local_access', '?h')))
        elif vuln.min_av == "ADJACENT":
            preconditions.append(','.join(('adjacent_access', '?h')))
        else:
            preconditions.append(','.join(('network_access', '?h')))
        if vuln.req_auth == 'YES':
            preconditions.append(','.join(('user_access', '?h')))
        precondition = ';'.join(preconditions)
        effect = ';'.join([','.join(['read_access', '?h']), ','.join(['compromised', '?h'])])
        return ':'.join(('action', vuln.name, parameters, precondition, effect))
    
    def action_access():
        parameters = ';'.join([format_pddl_type('host', ['?h']), format_pddl_type('file', ['?f'])])
        precondition = ';'.join([','.join(['read_access', '?h']), ','.join(['has_file', '?h', '?f']), ','.join(['network_access', '?h'])])
        effect = ','.join(['accessed', '?f'])
        return ':'.join(['action', 'access', parameters, precondition, effect])
    
    def action_update_access():
        parameters = ';'.join([format_pddl_type('host', ['?lh']), format_pddl_type('host', ['?rh'])])
        precondition = ';'.join([','.join(['connected', '?lh', '?rh']), ','.join(['compromised', '?lh']), ','.join(['network_access', '?lh'])])
        effect = ';'.join([','.join(['adjacent_access', '?rh']), ','.join(['network_access', '?rh'])])
        return ':'.join(['action', 'update_access', parameters, precondition, effect])
    
    for profile in profiles:
        print >> domain, '\n'.join([action_exploit(vuln) for vuln in profile.vuln_list])
    print >> domain, '\n'.join([action_access(), action_update_access()])
    
    ###############################################################################
    ## Problem - Init
    ##   The initial state begins with the label 'init' followed by a colon. 
    ##   The initial state is defined by a semicolon-delimited list of 
    ##   predicates, where each predicate is a comma-separated list of the 
    ##   predicate name and its parameters.
    ###############################################################################
    init = []
    
    file_host = random.choice([host.name for host in host_gen.get_hosts()])
    init.append(','.join(['has_file', file_host, 'File']))
    
    for host in host_gen.get_hosts():
        for neighbor in host.neighbors:
            init.append(','.join(['connected', host.name, neighbor]))
        for vuln in host.vulnerabilities:
            init.append(','.join(['has_vulnerability', host.name, vuln.name]))
        for access_level in host.access_levels:
            if access_level == "NETWORK":
                init.append(','.join(['network_access', host.name]))
            elif access_level == "ROOT":
                init.append(','.join(['read_access', host.name]))
                init.append(','.join(['compromised', host.name]))
            elif access_level == "USER":
                init.append(','.join(['user_access', host.name]))
                init.append(','.join(['read_access', host.name]))
                init.append(','.join(['compromised', host.name]))
    
    print >> problem, 'init:' + ';'.join(init)
    
    goal = 'goal:' + ';'.join(map(','.join,[('accessed', 'File')]))
    
    print >> problem, goal
    
    ###############################################################################
    ## Close files
    ###############################################################################
    
    domain.close()
    problem.close()
