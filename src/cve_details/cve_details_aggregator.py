import requests
from bs4 import BeautifulSoup
import re

ALL_CVE_URL = 'http://cve.mitre.org/data/downloads/allitems.txt'
CVE_DETAILS_URL = 'https://www.cvedetails.com/cve'
GOOGLE_PROXY_URL = 'https://g.jinzihao.info'
EXPLOIT_DB_URL = 'www.exploit-db.com'


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
        Update the CVEs in the __cves.
        :return: A dict of cve data.
        Format: [{'name': name0, 'port': [port0, port1, ...], 'apps': [{'Type': Type, 'Vendor': Vendor,
        'Product': Product, 'Version': Version}, ...]}, {...}, ...]
        """
        all_data = list()
        for cve in self.__cves:
            data = dict()
            html = requests.get(CVE_DETAILS_URL + '/' + cve).text
            html = re.sub(r'&#([^\d]+)', r'\1', html)
            soup = BeautifulSoup(html, 'html.parser')
            data['name'] = cve
            if 'Unknown CVE ID' in soup.text:  # illegal CVE ID
                data['ports'] = list()
                data['apps'] = list()
                data['cvss'] = None
                data['summary'] = None
            else:
                data['ports'] = CVEAggregator.__get_ports(soup)
                data['apps'] = CVEAggregator.__get_apps(soup)
                data['cvss'] = CVEAggregator.__get_cvss(soup)
                data['summary'] = CVEAggregator.__get_summary(soup)
            all_data.append(data)
        return all_data

    @staticmethod
    def get_all_cve():
        """
        Get the name of all the CVEs.
        :return: a list of CVE names.
        """
        txt = requests.get(ALL_CVE_URL).text
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
    def __get_summary(soup):
        summary = soup.find('div', class_='cvedetailssummary')
        for tag in summary.find_all():
            tag.extract()
        summary = summary.text
        summary = re.sub(r'[\n\r\t]', '', summary)
        return summary

    @staticmethod
    def __get_cvss(soup):
        cvss = soup.find('div', class_='cvssbox').text
        return float(cvss)

    @staticmethod
    def __get_apps(soup):
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
                    if app['Version'] == '-':
                        app['Version'] = None
                    apps.append(app)
                return apps
        else:
            return list()

    @staticmethod
    def __get_ports(soup):
        """
        Get the vulnerable ports of the CVE.
        :param soup: BeautifulSoup Object
        :return: a list of ports
        """
        summary = soup.find('div', class_='cvedetailssummary').text
        ports = re.findall(r'port (\d*)', summary)
        ports += re.findall(r'port \((\d*)\)', summary)
        ports += re.findall(r'(\d*)/tcp', summary)
        ports = list(filter(None, ports))  # remove empty strings
        return list(map(int, ports))

    @staticmethod
    def get_script(cve):
        """
        Get the testing script address.
        :param cve: the CVE name.
        :return: the urls of the testing script from exploit-db. Empty list if no scripts found.
        """
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_4) '
                          'AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.1 Safari/605.1.15'
        }
        html = requests.get(GOOGLE_PROXY_URL + '/search?q=' + cve + '%20' + 'site:' + EXPLOIT_DB_URL,
                            headers=headers).text
        soup = BeautifulSoup(html, 'html.parser')
        sites = soup.find_all('div', class_='g')
        scripts = list()
        for site in sites:
            script = site.find('cite')
            if script is not None:
                script = script.text
            else:  # images or something else, not scripts
                continue
            summary = site.find('span', class_='st').text
            re.sub(r'\s', '', summary)
            if cve in summary:
                scripts.append(script)
        return scripts


if __name__ == '__main__':
    import json
    # aggregator = CVEAggregator()
    # aggregator.set_cves(['CVE-2018-1170'])
    # print(json.dumps(aggregator.update_cves()))
    # print(json.dumps(CVEAggregator.get_script('CVE-2016-0989')))
