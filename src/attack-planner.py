#! /usr/bin/env python
# -*- coding: utf-8 -*-

################################################################################
## Imports
################################################################################

import os
import random
import sys
import subprocess
import time

from collections import defaultdict
from itertools import combinations, permutations
from StringIO import StringIO

from PDDL.PDDL_Formatter import *
from host_generator import HostGenerator
from nessus_parser import NessusParser
from vuln_profile import VulnProfile
from vuln_dict import VulnDict, VulnEntry

################################################################################
## Constants
################################################################################
PROBLEM_NAME = 'ER-Full'
DOMAIN_NAME = 'attack_planning'
ACCESS_PROBS = {}

if len(sys.argv) < 7:
    EVALUATION_TRIALS = 25
    HOST_NUM = 25
    CONNECTEDNESS = 2.5
    ACCESS_PROBS = {'NETWORK': 0.01,
                    'ROOT': 0.0,
                    'USER': 0.03}
    TOPOLOGY = "GEN-1"
    MARKER = ""
    TYPE = 'OPT'
else:
    EVALUATION_TRIALS = int(sys.argv[1])
    HOST_NUM = int(sys.argv[2])
    CONNECTEDNESS = float(sys.argv[3])
    ACCESS_PROBS['NETWORK'] = float(sys.argv[4])
    ACCESS_PROBS['ROOT'] = float(sys.argv[5])
    ACCESS_PROBS['USER'] = float(sys.argv[6])
    TOPOLOGY = sys.argv[7]
    MARKER = sys.argv[8]
    TYPE = sys.argv[9]

FILE_DIR = os.path.abspath(os.path.dirname(__file__))
FAST_DOWNWARD = os.path.join(FILE_DIR, '..', 'fast_downward', 'fast-downward.py')
DOMAIN_FILE = os.path.join(FILE_DIR, 'PDDL', 'data', 'domain.pddl')
PROBLEM_FILE = os.path.join(FILE_DIR, 'PDDL', 'data', 'problem.pddl')
OUTPUT_FILE = os.path.join(FILE_DIR, 'output' + MARKER + '.csv')

WIN_DESK_PATH = os.path.join(FILE_DIR, '..', 'PROFILES', 'Win7_2014_min.csv')
LIN_DESK_PATH = os.path.join(FILE_DIR, '..', 'PROFILES', 'Ubuntu_2014.csv')
WIN_SERV_PATH = os.path.join(FILE_DIR, '..', 'PROFILES', 'WinServer2012.csv')
LIN_SERV_PATH = os.path.join(FILE_DIR, '..', 'PROFILES', 'Ubuntu_Server_2014.csv')


###############################################################################
## Helper Functions
###############################################################################

def format_pddl_type(pddl_type, objects):
    """
    Formats pddl variables where pddl_type is a string and objects is 
    an iterable containing strings that are pddl variables of type pddl_type
    """
    return pddl_type + '|' + ','.join(objects)

def parse_predicate(p):
    items = p.split(';')
    yield items[0]
    for type_pair in items[1:]:
        t, variable_list = type_pair.split('|')
        yield getattr(types, t)(*variable_list.split(','))

def parse_parameters(p):
    for type_pair in p.split(';'):
        t, variable_list = type_pair.split('|')
        yield getattr(types, t)(*variable_list.split(','))

def parse_conditions(c):
    condition_list = [predicate(*item.split(',')) for item in c.split(';')]
    if len(condition_list) > 1:
        return and_(*condition_list)
    else:
        return condition_list[0]

def parse_action(a):
    _name, _parameters, _preconditions, _effects = a.split(':')
    return action(_name,
                  parameters(*parse_parameters(_parameters)),
                  precondition(parse_conditions(_preconditions)),
                  effect(parse_conditions(_effects)),
                  subindentation_level=2)

def parse_profiles(profile_paths):
    parser = NessusParser()
    PROFILES = []
    for path in profile_paths:
        report = parser.parse_report(path)
        profile = VulnProfile(report, VulnDict())
        profile.exclude_year(['2017', '2016', '2015'])
        profile.filter_zero_day()
        PROFILES.append(profile)

    return PROFILES

def generate_domain():
    domain_string = StringIO()

    ###############################################################################
    ## Domain - Types
    ##   The types begin with the label 'types' followed by a colon. 
    ##   A comma-separated list of types follows the label.
    ##   E.g. types:type1,type2,type3
    ###############################################################################
    
    print >> domain_string, 'types:' + ','.join(['host', 'vulnerability', 'file']) 
    
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
    print >> domain_string, 'constants:' + ':'.join((hosts_string, files))
    
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
    
    print >> domain_string, 'predicates:' + ':'.join((p_1, p_2, p_3, p_4, p_5, 
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
    
    for profile in profile_list:
        print >> domain_string, '\n'.join([action_exploit(vuln) for vuln in profile.vuln_list])
    print >> domain_string, '\n'.join([action_access(), action_update_access()])

    ################################################################################
    ## Aggregates the domain for the planner
    ################################################################################
    
    _types = set()
    _constants = defaultdict(set)
    _predicates = set()
    _actions = set()
    
    for line in domain_string:
        contents = line.split(':')
        if contents[0] == 'types':
            for item in contents[1].strip().split(','):
                _types.add(item)
        if contents[0] == 'constants':
            for type_pair in contents[1:]:
                t, constant_list = type_pair.strip().split('|')
                for c in constant_list.split(','):
                    _constants[t].add(c)
        if contents[0] == 'predicates':
            for p in contents[1:]:
                _predicates.add(p.strip())
        if contents[0] == 'action':
            _actions.add(':'.join(contents[1:]))
    
    # formatting
    types_ = types(*_types)
    constants_ = constants(*(getattr(types, k)(*v, sticky=1, subindentation_level=2) for k,v in _constants.items()),
                           sticky=0, subindentation_level=2)
    predicates_ = predicates(*(predicate(*parse_predicate(p)) for p in _predicates), 
                             sticky=1, subindentation_level=2)
    actions_ = (parse_action(a) for a in _actions)

    domain_ = domain(DOMAIN_NAME, has_colon=0)
    requirements_ = requirements(':strips', ':typing')

    define_ = define(domain_, 
                     requirements_, 
                     types_, 
                     constants_, 
                     predicates_, 
                     *actions_)

    print 'Generating aggregated domain:', DOMAIN_FILE
    with open(DOMAIN_FILE, 'w') as f:
        print >> f, define_

def generate_problem_instance():
    problem = StringIO()

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
        for neighbor in host.outgoing:
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
    
    print >> problem_string, 'init:' + ';'.join(init)
    
    goal = 'goal:' + ';'.join(map(','.join,[('accessed', 'File')]))
    
    print >> problem_string, goal
    
    ################################################################################
    ## Aggregates the full problem for the attack planner
    ################################################################################
    
    _goal = set()
    _init = set()
    
    for line in problem_string:
        contents = line.split(':')
        if contents[0] == 'init':
            for item in contents[1].split(';'):
                _init.add(tuple(item.strip().split(',')))
        if contents[0] == 'goal':
            for item in contents[1].split(';'):
                _goal.add(tuple(item.strip().split(',')))
    
    problem_ = problem(PROBLEM_NAME)
    domain_ = domain(DOMAIN_NAME)
    init_ = init(*(predicate(*item) for item in _init), subindentation_level=2)
    goal_ = goal(*(predicate(*goal) for goal in _goal), subindentation_level=2)
    define_ = define(problem_, domain_, init_, goal_)
    
    print 'Generating aggregated problem:', PROBLEM_FILE
    with open(PROBLEM_FILE, 'w') as p:
        print >> p, define_

# Generate vulnerability PROFILES
profile_list = parse_profiles([WIN_DESK_PATH, LIN_DESK_PATH, WIN_SERV_PATH, LIN_SERV_PATH])
PROFILES = {'GENERIC': [(0.7048, profile_list[0]), (0.2952, profile_list[1])],
            'SINGLETON': [(0.7048, profile_list[0]), (0.2952, profile_list[1])],
            'SERVER': [(0.336, profile_list[2]), (0.664, profile_list[3])],
            'GATEWAY': [(0.336, profile_list[2]), (0.664, profile_list[3])]}

# Run the host generator to initialize the topology and initial instance
host_gen = HostGenerator(HOST_NUM, TOPOLOGY, CONNECTEDNESS, ACCESS_PROBS, PROFILES)

# Generate the Domain
generate_domain()

if TYPE == 'EVAL':
    for _ in range(EVALUATION_TRIALS):
        start_time = time.time()

        # Generate the problem instance
        host_gen = HostGenerator(HOST_NUM, TOPOLOGY, CONNECTEDNESS, ACCESS_PROBS, PROFILES)
        generate_problem_instance()

        subprocess.call(['python', FAST_DOWNWARD, '--translate', DOMAIN_FILE, PROBLEM_FILE])
        subprocess.call(['python', FAST_DOWNWARD, 'output.sas', '--search', 'astar(lmcut())'])
    
        if os.path.exists(os.path.join(FILE_DIR, 'sas_plan')):
            successes += 1
        
        round_time = time.time() - start_time
        total_time += round_time

        print 'Time taken:', round_time
    
    print 'Average execution time', total_time / float(EVALUATION_TRIALS)
    print 'Number of vulnerable configurations: ', successes
    
    with open(OUTPUT_FILE, 'a') as w:
        print >> w, ','.join([str(EVALUATION_TRIALS), str(successes), str(total_time / float(EVALUATION_TRIALS)), str(HOST_NUM), 
                            str(CONNECTEDNESS), str(NETWORK_ACCESS_PROB), str(ROOT_ACCESS_PROB), 
                            str(USER_ACCESS_PROB)])

# Optimization approach
else:
    with open(OUTPUT_FILE, 'a') as w:
        print >> w, ','.join([str(EVALUATION_TRIALS), str(HOST_NUM),
                              str(CONNECTEDNESS), str(ACCESS_PROBS['NETWORK']),
                              str(ACCESS_PROBS['ROOT']), str(ACCESS_PROBS['USER'])])
        
        edge_list = []
        for host in host_gen.get_hosts():
            edge_list.extend(host.get_outgoing())
        print >> w, len(edge_list)

        while(best_prop > 0.05):
            best_edge = edge_list[0]
            best_prop = 1
            for edge in edge_list:
                for _ in range(EVALUATION_TRIALS):
                    start_time = time.time()
        
                    # Generate the problem instance
                    host_gen.generate_vulnerabilities()
                    host_gen.generate_access_levels()
                    generate_problem_instance()
        
                    subprocess.call(['python', FAST_DOWNWARD, '--translate', DOMAIN_FILE, PROBLEM_FILE])
                    subprocess.call(['python', FAST_DOWNWARD, 'output.sas', '--search', 'astar(lmcut())'])
        
                    if os.path.exists(os.path.join(FILE_DIR, 'sas_plan')):
                        successes += 1
        
                    round_time = time.time() - start_time
                    total_time += round_time
        
                prop = float(successes) / float(EVALUATION_TRIALS)
                
                if prop < best_prop:
                    best_prop = prop
                    best_edge = edge

                print 'Average execution time', total_time / float(EVALUATION_TRIALS)
                print 'Proportion of vulnerable configurations: ', prop
    
            print >> w, ','.join([best_edge, str(best_prop)])
            edge_list.remove(best_edge)
        