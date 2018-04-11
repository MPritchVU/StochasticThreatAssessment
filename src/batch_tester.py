'''
Created on Mar 15, 2017

@author: Michael
'''
import os
import subprocess
import math

def parse_line(line):
    line = line.split(',')
    if len(line) == 1:
        return line
    else:
        return range(int(line[0]), int(line[1]), int(line[2]))

if __name__ == '__main__':
    FILE_DIR = os.path.abspath(os.path.dirname(__file__))
    PLANNER_FILE = os.path.join(FILE_DIR, 'attack-planner.py')
    TEST_FILE = os.path.join(FILE_DIR, 'test_cases.csv')
    
    with open(TEST_FILE, 'r') as f:
        sets = int(f.readline())
        for _ in range(sets):
            trials = int(f.readline().strip('\r\n'))
            host_count = parse_line(f.readline().strip('\r\n'))
            connectedness = f.readline().strip('\r\n').split(',')
            network_access_prob = parse_line(f.readline().strip('\r\n'))
            root_access_prob = parse_line(f.readline().strip('\r\n'))
            user_access_prob = parse_line(f.readline().strip('\r\n'))
            topology = f.readline().strip('\r\n').split(',')
            label = f.readline().strip('\r\n')
            
            if topology[0] == "ER" and topology[1] == "NO":
                    connectedness = [int(val) for val in connectedness]
            topology = topology[0]

            for count in host_count:
                for connect in connectedness:
                    if connect == "NP1":
                        connect = 1.0 / float(count)
                    elif connect == "LNN":
                        connect = math.log(float(count)) / float(count)
                    for nap in [0.001*float(val) for val in network_access_prob]:
                        for root in root_access_prob:
                            for user in [0.001*float(uval) for uval in user_access_prob]:
                                subprocess.call(['python', PLANNER_FILE, str(trials), str(count), str(connect), str(nap), str(root), str(user), topology, label, '&'])
