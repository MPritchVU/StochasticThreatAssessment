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
from PDDL.PDDL_Formatter import *
from setup import setup
from vuln_profile import VulnProfile
from vuln_dict import VulnDict, VulnEntry

################################################################################
## Constants
################################################################################
total_time = 0
successes = 0
vd = VulnDict()

PROBLEM_NAME = 'ER-Full'
DOMAIN_NAME = 'attack_planning'

if len(sys.argv) < 7:
    EVALUATION_TRIALS = 25
    HOST_NUM = 1
    CONNECTEDNESS = 2.5
    NETWORK_ACCESS_PROB = 0.01
    ROOT_ACCESS_PROB = 0.0
    USER_ACCESS_PROB = 0.03
    TOPOLOGY = "GEN-1"
    MARKER = ""
else:
    EVALUATION_TRIALS = int(sys.argv[1])
    HOST_NUM = int(sys.argv[2])
    CONNECTEDNESS = float(sys.argv[3])
    NETWORK_ACCESS_PROB = float(sys.argv[4])
    ROOT_ACCESS_PROB = float(sys.argv[5])
    USER_ACCESS_PROB = float(sys.argv[6])
    TOPOLOGY = sys.argv[7]
    MARKER = sys.argv[8]

FILE_DIR = os.path.abspath(os.path.dirname(__file__))
FAST_DOWNWARD = os.path.join(FILE_DIR, '..', 'fast_downward', 'fast-downward.py')
DOMAIN_FILE = os.path.join(FILE_DIR, 'PDDL', 'data', 'domain' + MARKER + '.pddl')
PROBLEM_FILE = os.path.join(FILE_DIR, 'PDDL', 'data', 'problem' + MARKER + '.pddl')
SETUP_FILE = os.path.join(FILE_DIR, 'setup.py')
OUTPUT_FILE = os.path.join(FILE_DIR, 'output' + MARKER + '.csv')

VERSION = '1.0'

################################################################################
## Helper functions
################################################################################

def pause():
    raw_input('Press enter to continue...')

for _ in range(EVALUATION_TRIALS):
    start_time = time.time()

################################################################################
## Generate the Domain and Problem
################################################################################
    
#     if os.path.isfile(SETUP_FILE):
#         print 'Running setup file:', SETUP_FILE
#         subprocess.call(['python', SETUP_FILE, HOST_NUM, CONNECTEDNESS, NETWORK_ACCESS_PROB, ROOT_ACCESS_PROB, USER_ACCESS_PROB, EXPLOIT_SUCCESS_MOD])

    setup(HOST_NUM, CONNECTEDNESS, NETWORK_ACCESS_PROB, ROOT_ACCESS_PROB, USER_ACCESS_PROB, TOPOLOGY, vd, MARKER)
    
################################################################################
## Aggregates the domain for the planner
################################################################################
    
    _types = set()
    _constants = defaultdict(set)
    _predicates = set()
    _actions = set()
    
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
    
    with open(os.path.join(FILE_DIR, 'domain' + MARKER), 'r') as d:
        for line in d:
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
    
################################################################################
## Aggregates the full problem for the attack planner
################################################################################
    
    _goal = set()
    _init = set()
    
    with open(os.path.join(FILE_DIR, 'problem' + MARKER), 'r') as p:
        for line in p:
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
