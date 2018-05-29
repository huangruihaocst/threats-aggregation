import requests
from bs4 import BeautifulSoup

ALL_CVE_URL = 'http://cve.mitre.org/data/downloads/allitems.txt'
CVE_DETAILS_URL = 'https://www.cvedetails.com/cve'


class CVEAggregator:
    """
    The class grab details of every CVE but does not save them to database directly.
    """

    def __init__(self):
        self.__cves = list()  # no CVEs, public attribute

    def set_cves(self, cves):
        self.__cves = cves

    def clear_cves(self):
        self.__cves = list()

    def update_all(self):
        """
        Update all the CVEs.
        :return: the information of all CVEs.
        """
        all_cve = self.get_all_cve()
        self.__cves = all_cve
        return self.update_cves()

    def update_cves(self):
        """
        Update the CVEs in the task_list.
        :return: A dict of tasks.
        Format: [{'name': name0, 'port': [port0, port1, ...], 'apps': [{'Type': Type, 'Vendor': Vendor,
        'Product': Product, 'Version': Version}, ...]}, {...}, ...]
        """
        all_data = list()
        for cve in self.__cves:
            data = dict()
            html = requests.get(CVE_DETAILS_URL + '/' + cve).text
            soup = BeautifulSoup(html, 'html.parser')
            data['name'] = cve
            data['port'] = CVEAggregator.__get_ports(soup, html, '&#039;' not in html)
            data['apps'] = CVEAggregator.__get_apps(soup, html, '&#039;' not in html)
            all_data.append(data)
        return all_data

    @staticmethod
    def get_all_cve():
        """
        Get the name of all the CVEs.
        :return: a list of CVE names.
        """
        txt = requests.get(ALL_CVE_URL).text
        import re
        res = re.findall(r'Name: (CVE-\d{4}-\d{4})', txt)
        return list(set(res))

    @staticmethod
    def get_cve_by_years(years: list):
        """
        Get the name of all the CVEs within the specified years.
        :param years: a list of years.
        :return: a list of CVE names.
        """
        all_cve = CVEAggregator.get_all_cve()
        res_cve = list()
        for cve in all_cve:
            year = cve.split('-')[1]
            if int(year) in years:
                res_cve.append(cve)
        return res_cve

    @staticmethod
    def __get_apps(soup, html, use_bs):
        if use_bs:
            if 'Unknown CVE ID' in soup.text:  # illegal CVE ID
                return list()
            else:
                apps_table = soup.find('table', id='vulnprodstable')
        else:
            import re
            apps_table = re.findall(r'<table class="listtable" id="vulnprodstable">.*?</table>', html, re.S)[0]
            apps_table = BeautifulSoup(apps_table, 'html.parser')
        if apps_table is not None:
            if 'No vulnerable product found.' in apps_table.text:
                return list()
            else:
                trs = apps_table.find_all('tr')
                apps = list()
                for i in range(1, len(trs)):  # the first line is header
                    tds = trs[i].find_all('td')
                    app = dict()
                    app['Type'] = tds[1].text.strip()
                    app['Vendor'] = tds[2].find('a').text.strip()
                    app['Product'] = tds[3].find('a').text.strip()
                    app['Version'] = tds[4].text.strip()
                    apps.append(app)
                return apps
        else:
            return list()


    @staticmethod
    def __get_ports(soup, html, use_bs):
        """
        Get the vulnerable ports of the CVE.
        :param soup: BeautifulSoup Object
        :param html: the original html
        :param use_bs: if use BeautifulSoup. If the original html contains special chars, Beautiful cannot parse it
        :return: a list of ports
        """
        if use_bs:
            if 'Unknown CVE ID' in soup.text:  # illegal CVE ID
                return list()
            else:
                import re
                summary = soup.find('div', class_='cvedetailssummary').text
        else:
            import re
            summary = re.findall(r'<div class="cvedetailssummary">.*?</div>', html, re.S)[0]
            summary = BeautifulSoup(summary, 'html.parser').text
        ports = re.findall(r'port (\d*)', summary)
        ports += re.findall(r'port \((\d*)\)', summary)
        ports += re.findall(r'(\d*)/tcp', summary)
        ports = list(filter(None, ports))  # remove empty strings
        return list(map(int, ports))


if __name__ == '__main__':
    import json
    aggregator = CVEAggregator()
    # aggregator.set_tasks(['CVE-2018-0171', 'CVE-2007-6372', 'CVE-2018-1000179', 'CVE-2007-1833'])
    # print(json.dumps(aggregator.update_tasks()))
    # with open('1.txt', 'w') as f:
    #     f.write(json.dumps(aggregator.get_cve_by_years([1999])))
    aggregator.set_cves(['CVE-1999-1343'])
    print(json.dumps(aggregator.update_cves()))
