'''
Created on Feb 15, 2017

@author: Michael
'''

from vuln_dict import VulnDict, VulnEntry


class VulnProfile(object):
    def __init__(self, parsed_report, vd, name):
        self.name =  name
        self.vuln_list = []
        duplicate_list = []
        
        for entry in parsed_report[1:]:
            if entry[0] not in vd.vuln_dict:
                continue
            vuln = vd.vuln_dict[entry[0]]
            # Ignore vulnerabilities which do not have confidentiality
            if vuln.cvss['Confidentiality Impact'] == 'NONE':
                continue
            if entry[1].split(':')[0] in duplicate_list:
                continue
            else:
                duplicate_list.append(entry[1].split(':')[0])
            name = vuln.id
            cwe = vuln.cwe
            published_date = vuln.published_date
            min_av = vuln.cvss['Access Vector']
            req_auth = 'NO' if vuln.cvss['Authentication'] == 'NONE' else 'YES'
            conf = vuln.cvss['Confidentiality Impact']
            probability = self.determine_probability(vuln)
            self.vuln_list.append(Vulnerability(name, min_av, req_auth, conf, probability, cwe, published_date))
        print("Vulnerability profile contains " + str(len(self.vuln_list)) + " vulnerabilities")

    def get_vulnerabilities(self):
        return [vuln.name for vuln in self.vuln_list]

    def add_vulnerability(self, vuln):
        self.vuln_list.append(vuln)

    def remove_vulnerability(self, vuln_name):
        for vuln in self.vuln_list:
            if vuln.name == vuln_name:
                self.vuln_list.remove(vuln)

    def determine_probability(self, vuln):
        prob = 1.0
        if vuln.cvss['Authentication'] == 'MULTIPLE':
            prob = prob * 0.8
        
        ac = vuln.cvss['Access Complexity']
        if ac == "HIGH":
            prob = prob * 0.35
        elif ac == "MEDIUM":
            prob = prob * 0.61
        else:
            prob = prob * 0.71

        conf = vuln.cvss['Confidentiality Impact']
        if conf == 'COMPLETE':
            prob = prob*0.660
        elif conf == 'PARTIAL':
            prob = prob*0.275
            
        return prob

    def exclude_year(self, year):
        vuln_list = []
        for vuln in self.vuln_list:
            vuln_name = vuln.name.split('-')
            if vuln_name[1] not in year:
                vuln_list.append(vuln)

        self.vuln_list = vuln_list
        print("Filtered vulnerability profile contains " + str(len(self.vuln_list)) + " vulnerabilities")

    def filter_zero_day(self):
        vuln_list = []
        for vuln in self.vuln_list:
            date = vuln.name.split('-')[1]
            pub_date = vuln.published_date.split('-')[0]
            if date == pub_date:
                vuln_list.append(vuln)

        self.vuln_list = vuln_list
        print("Filtered vulnerability profile contains " + str(len(self.vuln_list)) + " vulnerabilities")

#     def count_zero_day(self):
#         vuln_list = []
#         for vuln in self.vuln_list:
#             date = vuln.name.split('-')[1]
#             pub_date = vuln.published_date.split('-')[0]
#             if date == pub_date:
#                 vuln_list.append(vuln)
#  
#         proportion = float(len(vuln_list)) / float(len(self.vuln_list))
#         print("Profile zero-day proportion: " + str(proportion))

class Vulnerability(object):
    def __init__(self, name, min_av, req_auth, conf, probability, cwe, pub_date):
        self.name = name
        self.min_av = min_av
        self.req_auth = req_auth
        self.probabilty = probability
        self.confidentiality = conf
        self.cwe = cwe
        self.published_date = pub_date