from src.aggregate.censys_aggregator import CensysAggregator
from src.aggregate.shodan_aggregator import ShodanAggregator
from src.aggregate.zoomeye_aggregator import ZoomEyeAggregator
from src.cve_details.cve_details_aggregator import CVEAggregator
from src.aggregate.query import QueryType, Query
from src.utils.mongo_helper import MongoHelper
from src.notification.notifier import Notifier
from threading import Thread, Lock, current_thread
import json
from datetime import datetime

BUFFER_SIZE = 100
THREADS = 8
CVE_START_YEAR = 1999
UPDATE_CYCLE = 7 * 24 * 60  # a week
IGNORE_PORTS = [80, 443]
CVSS_THRESHOLD = 8


def remove_dots(d: dict):
    """
    Remove dots in dictionary and replace it with underline.
    :param d: a nested dictionary.
    :return: new dictionary that all dots have been removed from keys.
    """
    new_dict = dict()
    for key, value in d.items():
        if isinstance(value, dict):
            value = remove_dots(value)
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    index = value.index(item)
                    item = remove_dots(item)
                    value[index] = item
        new_dict[key.replace('.', '_')] = value
    return new_dict


def has_same_item(l1: list, l2: list):
    for item in l1:
        if item in l2:
            return True
    return False


def longest_match(s1: str, s2: str):
    """
    Find the length of longest substring of s1 and s2.
    :param s1: string 1
    :param s2: string 2
    :return: the length of the longest substring
    """
    if s1 is None or s2 is None:
        return 0
    from difflib import SequenceMatcher
    match = SequenceMatcher(None, s1.lower(), s2.lower()).find_longest_match(0, len(s1), 0, len(s2))
    return match.size


class Controller:
    """
    The class controls the process of aggregating threats and details of CVEs, and also analysis.
    """

    def __init__(self):
        self.__queries = list()
        self.__cves = list()

    def start_aggregate(self):
        """
        Start aggregation. The actual aggregation is done once in a well.
        It must be run in a different thread.
        :return: None
        """
        # step 1: read queries from file, get the queries
        self.__read_queries()

        # step 2: read CVE range from file
        self.__read_cves()

        print('Initialization done.')

        # step 3: start aggregation
        self.aggregate_hosts()
        print('Aggregating hosts done.')
        self.aggregate_cve_details()
        print('Aggregating CVEs done.')
        Controller.analyze()
        print('Analysis done.')

        # step 4: write to last update
        with open('last_updated.txt', 'w') as f:
            now = datetime.now()
            f.write(str(now))

        # step 5: notification
        notifier = Notifier()
        total = MongoHelper.get_threats_count()
        with open('config.json') as f:
            config = json.loads(f.read())
            cves = config['notification']['CVEs']
            specials = list()
            for cve in cves:
                special = dict()
                special['name'] = cve
                special['count'] = MongoHelper.read_threats_by_cve(cve).count()
                specials.append(special)
        notifier.notify(total, specials)

    @staticmethod
    def analyze():
        """
        Use hosts data and CVE data to analyze which hosts are vulnerability.
        Save the result into database.
        Format: [{'ip': ip0, 'query': query0, 'CVEs': {CVE0: {'ports': [...], 'apps': [...], 'source': 'CVE Details'}, ...]
        :return: None
        """
        import datetime
        from copy import deepcopy
        MongoHelper.drop_threats_collection()
        read_hosts = MongoHelper.read_all_hosts()
        hosts = deepcopy(read_hosts)
        done = 0
        lock = Lock()

        def get_analyzer():
            nonlocal hosts, done

            while len(hosts) > 0:
                lock.acquire()
                try:
                    current, hosts = hosts[:BUFFER_SIZE], hosts[BUFFER_SIZE:]
                finally:
                    lock.release()

                all_vulns = list()
                for host in current:
                    # step 1: initialization
                    vulns = dict()
                    vulns['ip'] = host['ip']
                    vulns['query'] = host['query']
                    vulns['CVEs'] = dict()

                    # step 2: read the vulnerabilities given by Shodan
                    shodan_vulns = dict()
                    if 'data' in host:
                        for data in host['data']:
                            if 'vulns' in data:
                                for vuln in data['vulns']:
                                    if vuln not in shodan_vulns.keys() \
                                            and float(data['vulns'][vuln]['cvss']) >= CVSS_THRESHOLD:
                                        shodan_vulns[vuln] = data['vulns'][vuln]
                    if len(shodan_vulns) > 0:
                        for vuln in shodan_vulns:
                            shodan_vulns[vuln]['source'] = 'Shodan'
                        vulns['CVEs'] = shodan_vulns

                    # step 3: use apps and ports to find other vulnerabilities
                    for year in range(CVE_START_YEAR, datetime.datetime.now().year + 1):
                        cves = MongoHelper.read_cves_by_year(year)
                        for cve in cves:
                            if cve['cvss'] < CVSS_THRESHOLD:
                                continue
                            vuln_ports, vuln_apps = Controller.__is_vulnerable(host, cve)
                            if len(vuln_ports) + len(vuln_apps) > 0:
                                if cve['name'] not in vulns['CVEs']:
                                    vuln = dict()
                                    vuln['ports'] = vuln_ports
                                    vuln['apps'] = vuln_apps
                                    vuln['source'] = 'CVE Details'
                                    vulns['CVEs'][cve['name']] = vuln
                                else:
                                    vulns['CVEs'][cve['name']]['ports'] = vuln_ports
                                    vulns['CVEs'][cve['name']]['apps'] = vuln_apps
                                    vulns['CVEs'][cve['name']]['source'] = 'Shodan/CVE Details'

                    if len(vulns['CVEs']) > 0:
                        all_vulns.append(vulns)

                    print(current_thread().name + ' ' + host['ip'] + ' done.')

                # step 4: save to database
                if len(all_vulns) > 0:
                    MongoHelper.save_threats(all_vulns)
                lock.acquire()
                try:
                    done += len(all_vulns)
                    print('>>>>>>> ' + current_thread().name + ' ' + str(done) + ' done.')
                finally:
                    lock.release()

        workers = list()
        for i in range(0, THREADS):
            worker = Thread(target=get_analyzer)
            worker.start()
            workers.append(worker)
        for worker in workers:
            worker.join()

    @staticmethod
    def __get_host_apps(host):
        """
        Get the apps of a host, including OS, webapp, framework and so on.
        :param host: host information.
        :return: a list of apps.
        format: [{'name': name0, 'version': version0}, {...}, ...]
        """
        apps = list()
        # from Shodan
        if 'data' in host:
            for data in host['data']:
                if 'product' in data:
                    app = dict()
                    app['name'] = data['product']
                    app['version'] = data['version'] if 'version' in data else None
                    apps.append(app)
            if 'http' in host['data'] and 'components' in host['data']['http'] \
                    and len(host['data']['http']['components']) > 0:
                for component in host['data']['http']['components']:
                    apps.append({'name': component, 'version': None})
        # from ZoomEye
        app_types = ['component', 'db', 'webapp', 'server', 'framework', 'waf']
        for app_type in app_types:
            if app_type in host and len(host[app_type]) > 0:
                for app in host[app_type]:
                    app_dict = dict()
                    app_dict['name'] = app['name']
                    if 'version' in app:
                        app_dict['version'] = app['version']
                    else:
                        app_dict['version'] = None
                    apps.append(app_dict)
        if 'system' in host and len(host['system']) > 0:
            for system in host['system']:
                app = dict()
                app['name'] = system['distrib'] if system['distrib'] is not None else system['name']
                if 'version' in system:
                    app['version'] = system['version']
                else:
                    app['version'] = None
                apps.append(app)
        if 'language' in host and len(host['language']) > 0:
            for language in host['language']:
                apps.append({'name': language, 'version': None})
        return apps

    @staticmethod
    def __get_host_ports(host):
        """
        Get all the open ports of the host.
        :param host: host information.
        :return: A list of open ports.
        format: [port0, port1, ...]
        """
        ports = list()
        if 'protocols' in host:
            for protocol in host['protocols']:
                ports.append(int(protocol.split('/')[0]))
        if 'ports' in host:
            ports += host['ports']
        ports = list(set(ports))
        return ports

    @staticmethod
    def __is_vulnerable(host, cve):
        """
        Check if the host is vulnerable to the certain CVE.
        :param host: host information
        :param cve: CVE information
        :return: The reason why it is vulnerable.
        format: ports: list, apps: list (tuple)
        """
        # step 1: merge app list
        apps = Controller.__get_host_apps(host)

        # step 2: merge ports list
        ports = Controller.__get_host_ports(host)

        # step 3: compare with CVE data
        if len(cve['ports']) == 0 and len(cve['apps']) == 0:
            return list(), list()
        else:
            # condition: (one of the ports) or (one of the apps)
            vuln_ports = list(set(ports).intersection(cve['ports']))
            for port in IGNORE_PORTS:
                if port in vuln_ports:
                    vuln_ports.remove(port)
            vuln_apps = list()
            for cve_app in cve['apps']:
                for app in apps:
                    # same app strategy: scoring
                    score, pass_score = 0, 0.9
                    if not (cve_app['Product'] is None or len(cve_app['Product']) == 0
                            or app['name'] is None or len(app['name']) == 0):
                        score += longest_match(cve_app['Product'], app['name']) \
                                 / (len(app['name']) + len(cve_app['Product']) / 2)
                    if score > 0.75:  # almost the same app
                        pass_score = 1.5
                    elif score < 0.5:
                        continue  # not even the same app
                    if cve_app['Version'] is None or len(cve_app['Version']) == 0 \
                            or app['version'] is None or len(app['version']) == 0:
                        score += 0.125
                    else:
                        import re
                        cve_app['Version'] = re.sub(r'^[\d.]', '', cve_app['Version'])
                        cve_versions = cve_app['Version'].split('.')
                        app_versions = app['version'].split('.')
                        if len(cve_versions) > 0 and len(app_versions) > 0 and cve_versions[0] == app_versions[0]:
                            score += 0.25
                            if len(cve_versions) > 1 and len(app_versions) > 1 and cve_versions[1] == app_versions[1]:
                                score += 0.5
                                if len(cve_versions) > 2 and len(app_versions) > 2 and cve_versions[2] == app_versions[2]:
                                    score += 0.75
                    if score > pass_score and app not in vuln_apps:
                        vuln_apps.append(app)
            return vuln_ports, vuln_apps

    def __read_queries(self):
        with open('config.json') as f:
            config = json.loads(f.read())
        for query in config['queries']:
            if query['type'] == 'hostname':
                self.__queries.append(Query(query['query'], QueryType.hostname))
            elif query['type'] == 'net':
                self.__queries.append(Query(query['query'], QueryType.net))
            elif query['type'] == 'ip':
                self.__queries.append(Query(query['query'], QueryType.ip))
            else:
                print('Invalid query type: ' + query['type'])

    def aggregate_hosts(self):
        """
        Aggregate hosts from Censys, Shodan and ZoomEye.
        :return: None
        """

        # step 1: initialize query list for aggregator
        censys_aggregator = CensysAggregator()
        censys_aggregator.set_queries(self.__queries)
        shodan_aggregator = ShodanAggregator()
        shodan_aggregator.set_queries(self.__queries)
        zoom_eye_aggregator = ZoomEyeAggregator()
        zoom_eye_aggregator.set_queries(self.__queries)

        # step 2: fetch all
        censys_res = censys_aggregator.fetch_all()
        print('censys done.')
        shodan_res = shodan_aggregator.fetch_all()
        print('shodan done.')
        zoom_eye_res = zoom_eye_aggregator.fetch_all()
        print('zoomeye done.')

        # step 3: merge
        merged_res = Controller.__merge(censys_res, shodan_res, zoom_eye_res)
        print('merging done.')

        # step 4: save to database
        MongoHelper.drop_hosts_collection()
        MongoHelper.save_hosts(merged_res)

    @staticmethod
    def __merge(censys_res, shodan_res, zoom_eye_res):
        """
        Merge host information from different sources and attach apps information to each host.
        The method is source sensitive. Adding new source requires rewriting of this method.
        :return: a merged dict.
        Format: {query0: [{field0: data0, field1: data1, ...}, {...}], query1: ...}
        """
        assert censys_res.keys() == shodan_res.keys() == zoom_eye_res.keys()
        merged = Controller.__merge_res(censys_res, shodan_res, zoom_eye_res)

        # postprocess
        for query in merged:
            for host in merged[query]:
                index = merged[query].index(host)
                # Mongodb can only handle up to 64-bits int
                if 'data' in host:
                    for data in host['data']:
                        if 'ssl' in data and 'cert' in data['ssl'] and 'serial' in data['ssl']['cert']:
                            data['ssl']['cert']['serial'] = str(data['ssl']['cert']['serial'])
                        # MongoDb cannot handle unicode and html is actually useless in this way
                        if 'html' in data:
                            data.pop('html')
                        if 'http' in data:
                            if 'html' in data['http']:
                                data['http'].pop('html')
                # Mongodb cannot handle key name with dots.
                host = remove_dots(host)
                merged[query][index] = host
        return merged

    @staticmethod
    def __merge_res(censys_res, shodan_res, zoom_eye_res):
        from copy import deepcopy
        merged_res = dict()
        for query in censys_res:
            censys = censys_res[query]  # type: list
            shodan = shodan_res[query]  # type: list
            zoom_eye = zoom_eye_res[query]  # type: list
            merged_res[query] = list()  # the final merged result
            # step 1: merge censys and shodan
            mid_merged_res = list()  # the list used to contain the merged result of Censys and Shodan
            for censys_host in censys:
                ip = censys_host['ip']
                # there won't be identical ip address in shodan_res
                shodan_corr = [host for host in shodan if host['ip_str'] == ip]
                if len(shodan_corr) > 0:  # same ip address in Censys and Shodan
                    merged = censys_host
                    corr_copy = deepcopy(shodan_corr[0])
                    corr_copy.pop('ip')
                    corr_copy.pop('ip_str')
                    corr_copy.pop('source')
                    merged = dict({**merged, **corr_copy})
                    if 'tags' in shodan_corr[0]:
                        merged['tags'] += corr_copy['tags']
                    merged['source'] = 'Censys/Shodan'
                    mid_merged_res.append(merged)
                    shodan = [host for host in shodan if host not in shodan_corr]
                else:  # no corresponding result in Shodan
                    shodan_additional = ShodanAggregator.get_info_by_ip(censys_host['ip'])
                    # at least there will be a 'ip_str' field
                    if len(shodan_additional) > 1:  # new information from Shodan
                        shodan_additional.pop('ip')
                        shodan_additional.pop('ip_str')
                        censys_host = dict({**censys_host, **shodan_additional})
                        censys_host['source'] = 'Censys/Shodan'
                    mid_merged_res.append(censys_host)
            # no need to search Censys again, add the rest directly to merged result
            for shodan_host in shodan:  # no corresponding in Censys
                shodan_host['ip'] = shodan_host['ip_str']
                shodan_host.pop('ip_str')
                mid_merged_res.append(shodan_host)
            print('merge censys and shodan done.')
            # step 2: merge censys+shodan and zoom_eye
            for merged in mid_merged_res:
                ip = merged['ip']
                zoom_eye_corr = [host for host in zoom_eye if host['ip'][0] == ip]
                if len(zoom_eye_corr) > 0:  # same ip address in merged and ZoomEye
                    zoom_eye_latest = ZoomEyeAggregator.get_latest(zoom_eye_corr)
                    corr_copy = deepcopy(zoom_eye_latest)
                    corr_copy.pop('ip')
                    corr_copy.pop('geoinfo')
                    source_saved = merged['source']  # in order not to be covered by merging dict
                    merged = dict({**merged, **corr_copy})
                    merged['source'] = source_saved + '/ZoomEye'
                    merged_res[query].append(merged)
                    zoom_eye = [host for host in zoom_eye if host not in zoom_eye_corr]
                else:  # no corresponding in ZoomEye
                    zoom_eye_additional = ZoomEyeAggregator.get_info_by_ip(merged['ip'])
                    if len(zoom_eye_additional) > 0:  # new information from ZoomEye
                        zoom_eye_additional.pop('ip')
                        zoom_eye_additional.pop('geoinfo')
                        source_saved = merged['source']  # in order not to be covered by merging dict
                        merged = dict({**merged, **zoom_eye_additional})
                        merged['source'] = source_saved + '/ZoomEye'
                    merged_res[query].append(merged)
            for zoom_eye_host in zoom_eye:  # no corresponding in merged
                zoom_eye_host['ip'] = zoom_eye_host['ip'][0]
                zoom_eye_host.pop('geoinfo')
                # no need to search Censys again
                shodan_additional = ShodanAggregator.get_info_by_ip(zoom_eye_host['ip'])
                if len(shodan_additional) > 1:  # new information from Shodan
                    shodan_additional.pop('ip')
                    shodan_additional.pop('ip_str')
                    source_saved = zoom_eye_host['source']  # in order not to be covered by merging dict
                    zoom_eye_host = dict({**zoom_eye_host, **shodan_additional})
                    zoom_eye_host['source'] = source_saved + '/Shodan'
                merged_res[query].append(zoom_eye_host)
        return merged_res

    def __read_cves(self):
        with open('config.json') as f:
            config = json.loads(f.read())
        if config['CVE']['all']:
            self.__cves = CVEAggregator.get_all_cve()
        else:
            print(config['CVE']['years'])
            self.__cves = CVEAggregator.get_cve_by_years(config['CVE']['years'])
            for cve in config['CVE']['others']:
                self.__cves.append(cve)
            self.__cves = list(set(self.__cves))
            print('CVE complete.')

    def aggregate_cve_details(self):
        """
        Aggregate threats from www.cvedetails.com. Incremental Update.
        :return: None
        """

        # step 1: initialization
        print('total: ' + str(len(self.__cves)))
        MongoHelper.drop_cves_collection()
        from copy import deepcopy
        cves = deepcopy(self.__cves)

        # step 2: start aggregation (multi-threaded)
        done = 0
        lock = Lock()

        def get_aggregator():
            nonlocal cves, done
            while len(cves) > 0:
                lock.acquire()
                try:
                    current, cves = cves[:BUFFER_SIZE], cves[BUFFER_SIZE:]
                finally:
                    lock.release()
                cve_aggregator = CVEAggregator()
                cve_aggregator.set_cves(current)
                res = cve_aggregator.update_cves()
                # step 3: save to database
                MongoHelper.save_cves(res)
                lock.acquire()
                try:
                    done += len(res)
                    print(current_thread().name + ' ' + str(done) + ' done.')
                finally:
                    lock.release()

        workers = list()
        for i in range(0, THREADS):
            worker = Thread(target=get_aggregator)
            worker.start()
            workers.append(worker)
        for worker in workers:
            worker.join()


if __name__ == '__main__':
    # import time
    # while True:
    #     controller = Controller()
    #     controller.start_aggregate()
    #     time.sleep(UPDATE_CYCLE)
    controller = Controller()
    controller.analyze()
