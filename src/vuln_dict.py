import os
import pickle
import untangle

REPO = os.path.join('..', 'NVD')

def main():
    a = VulnDict()
    a.parse_zero_day()

class VulnDict(object):
    def __init__(self):
        self.vuln_dict = dict()
        dict_loc = os.path.join(REPO, 'vuln_dict')
        if not os.path.isfile(dict_loc):
            for f in os.listdir(REPO):
                file_path = os.path.join(REPO, f)
                converted_xml = untangle.parse(file_path)
                
                for entry in converted_xml.nvd.entry:
                    if not hasattr(entry, 'vuln_cvss'):
                        continue
                    cve_id = entry.vuln_cve_id
                    cvss = entry.vuln_cvss
                    cwe = entry.vuln_cwe if hasattr(entry, 'vuln_cwe') else None
                    published_date = entry.vuln_published_datetime
                    self.vuln_dict[entry['id']] = VulnEntry(cve_id, cvss, published_date, cwe)
            pickle.dump(self.vuln_dict, open(dict_loc, 'w'))
        else:
            self.vuln_dict = pickle.load(open(dict_loc, 'r'))

    def parse_zero_day(self):
        vuln_count = {}
        zero_day_count = {}
        for year in range(2002, 2017, 1):
            vuln_count[str(year)] = 0
            zero_day_count[str(year)] = 0
        for vuln in self.vuln_dict.values():
            date = vuln.id.split('-')[1]
            pub_date = vuln.published_date.split('-')[0]
            if int(date) >= 2002 and int(date) <= 2016:
                if date != pub_date:
                    zero_day_count[str(date)] = zero_day_count[str(date)] + 1
                vuln_count[str(date)] = vuln_count[str(date)] + 1
            
        total_vuln = sum(vuln_count.values())
        total_zero_day = sum(zero_day_count.values())
        print("Zero-day Vulnerability Statistics")
        for year in range(2002, 2017, 1):
            zero_days = zero_day_count[str(year)]
            vulns = vuln_count[str(year)]
            print(str(year) + ": " + str(zero_days) + " / " + str(vulns) + " = " + str(float(zero_days) / float(vulns)))
        print("Total: " + str(total_zero_day) + " / " + str(total_vuln) + " = " + str(float(total_zero_day) / float(total_vuln)))
        self.zero_day = float(total_zero_day) / float(total_vuln)

class VulnEntry(object):
    def __init__(self, vuln_id, cvss, published_date, cwe):
        self.id = vuln_id.cdata
        self.cvss = self.parse_cvss(cvss.cvss_base_metrics)
        self.published_date = published_date.cdata
        try:
            self.cwe = '' if cwe is None else cwe['id']
        except TypeError:
            self.cwe = ''
 
    def parse_cvss(self, cvss):
        cvss_dict = dict()
        cvss_dict['Score'] = cvss.cvss_score.cdata
        cvss_dict['Access Complexity'] = cvss.cvss_access_complexity.cdata
        cvss_dict['Access Vector'] = cvss.cvss_access_vector.cdata
        cvss_dict['Authentication'] = cvss.cvss_authentication.cdata
        cvss_dict['Availability Impact'] = cvss.cvss_availability_impact.cdata
        cvss_dict['Confidentiality Impact'] = cvss.cvss_confidentiality_impact.cdata
        cvss_dict['Integrity Impact'] = cvss.cvss_integrity_impact.cdata
        
        return cvss_dict

if __name__ == "__main__":
    main()
