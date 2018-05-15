import requests
from bs4 import BeautifulSoup

ALL_CVE_URL = 'http://cve.mitre.org/data/downloads/allitems.txt'
CVE_DETAILS_URL = 'https://www.cvedetails.com/cve'


class CVEAggregator:
    """
    The class grab details of every CVE but does not save them to database directly.
    """

    def __init__(self):
        self.__tasks = list()  # no tasks, public attribute

    def set_tasks(self, tasks):
        self.__tasks = tasks

    def clear_tasks(self):
        self.__tasks = list()

    def update_all(self):
        """
        Update all the CVEs.
        :return:
        """
        all_cve = self.get_all_cve()
        self.__tasks = all_cve
        return self.update_tasks()

    def update_tasks(self):
        """
        Update the CVEs in the task_list.
        :return: A dict of tasks.
        Format: {'task0': {'port': [port0, port1, ...], 'apps': [{'Type': Type, 'Vendor': Vendor, 'Product': Product,
         'Version': Version}, ...]}, 'task1': ...}
        """
        all_data = dict()
        for task in self.__tasks:
            data = dict()
            html = requests.get(CVE_DETAILS_URL + '/' + task).text
            soup = BeautifulSoup(html, 'html.parser')
            data['port'] = self.__get_ports(soup)
            data['apps'] = self.__get_app(soup)
            all_data[task] = data
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
    def __get_app(soup):
        if 'Unknown CVE ID' in soup.text:  # illegal CVE ID
            return None
        else:
            apps_table = soup.find('table', id='vulnprodstable')
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
                return None

    @staticmethod
    def __get_ports(soup):
        summary = soup.find('div', class_='cvedetailssummary').text
        import re
        ports = re.findall(r'port (\d*)', summary)
        ports += re.findall(r'(\d*)/tcp', summary)
        return list(map(int, ports))


if __name__ == '__main__':
    import json
    aggregator = CVEAggregator()
    aggregator.set_tasks(['CVE-2018-0171', 'CVE-2007-6372', 'CVE-2018-1000179', 'CVE-2007-1833'])
    print(json.dumps(aggregator.update_tasks()))
