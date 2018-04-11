"""
nessus_parser.py

Parses Nessus vulnerability reports (CSV).

@author: Michael Pritchard
"""

import os
from vuln_profile import VulnProfile
from vuln_dict import VulnDict, VulnEntry

def main():
    report_path = os.path.join('.', 'Win7_2014_min.csv')
    parser = NessusParser()
    report = parser.parse_report(report_path)
    vp = VulnProfile(report)
    print(len(vp.vuln_list))
    
class NessusEntry():
    def __init__(self,cve, name):
        self.cve = cve
        self.name = name

class NessusParser(object):
    def __init__(self):
            pass

    def parse_report(self, report):
        entries = []
        
        with open(report, 'r') as rep:
            for line in rep:
                contents = line.split(',')
                if contents[0] != '':
                    entries.append(contents)

        return entries

if __name__ == "__main__":
    main()