from src.aggregate.censys_aggregator import CensysAggregator
from src.aggregate.shodan_aggregator import ShodanAggregator
from src.aggregate.zoomeye_aggregator import ZoomEyeAggregator
from src.cve_details.cve_details_aggregator import CVEAggregator
from src.aggregate.query import QueryType, Query
from src.utils.mongo_helper import MongoHelper
from threading import Thread, Lock, current_thread

CVE_BUFFER_SIZE = 100
THREADS = 8
CVE_START_YEAR = 1999


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
    from difflib import SequenceMatcher
    match = SequenceMatcher(None, s1.lower(), s2.lower()).find_longest_match(0, len(s1), 0, len(s2))
    return match.size

class AggregatorController:
    """
    The class controls the process of aggregating threats and details of CVEs.
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
        self.aggregate_hosts()
        self.aggregate_cve_details()
        self.analyze()

    def analyze(self):
        """
        Use threats data and CVE data to analyze which hosts are vulnerability.
        Save the result into database.
        Format: {query0: [{'ip': ip0, 'CVEs': ['name': name0, 'ports': [...], 'apps': [...], 'source': 'CVE Details'], ...}
        :return: None
        """
        import datetime
        # self.__queries = ['166.111.0.0/21']  # TODO: should be removed
        all_vulns = dict()
        # for query in self.__queries:  # each query
        #     # check if there are vulnerabilities by year
        #     all_vulns[query] = list()
        #     for host in MongoHelper.read_hosts_by_query(query):
        #         for
        #     for year in range(CVE_START_YEAR, datetime.datetime.now().year + 1):
        #         cves_cursor = MongoHelper.read_cves_by_year(year)
        #         for cve in cves_cursor:  # each CVE
        #             hosts_cursor =
        #             for host in hosts_cursor:  # each host
        #                 vuln_ports, vuln_apps = AggregatorController.__is_vulnerable(host, cve)
        #                 if len(vuln_ports) > 0 or len(vuln_apps) > 0:
        #                     vulns = dict()



    @staticmethod
    def __get_host_apps(host):
        """
        Get the apps of a host, including OS, webapp, framework and so on.
        :param host: the ip address of the host.
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
                app['name'] = system['distrib']
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
        :param host: the ip address of the host.
        :return: A list of open ports.
        format: [port0, port1, ...]
        """
        ports = list()
        if 'protocols' in host:
            for protocol in host['protocols']:
                ports.append(int(protocol.split('/')[0]))
        if 'port' in host:
            if host['port'] not in ports:
                ports.append(host['port'])
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
        apps = AggregatorController.__get_host_apps(host)

        # step 2: merge ports list
        ports = AggregatorController.__get_host_ports(host)

        # step 3: compare with CVE data
        if len(cve['ports']) == 0 and len(cve['apps']) == 0:
            return False, list(), list()
        else:
            # condition: (one of the ports) or (one of the apps)
            vuln_ports = list(set(ports).intersection(cve['ports']))
            vuln_apps = list()
            for cve_app in cve['apps']:
                for app in apps:
                    # same app strategy: scoring
                    score = 0
                    score += longest_match(cve_app['Name'], app['name']) / min(cve_app['Name'], app['name'])
                    if cve_app['version'] is None or app['version'] is None:
                        score += 0.5
                    else:
                        score += longest_match(cve_app['Version'], app['version']) / cve_app['Version'], app['version']
                    if score > 1:
                        vuln_apps.append(app)
            return vuln_ports, vuln_apps

    def __read_queries(self):
        # TODO: read queries from file
        query = Query('166.111.0.0/16', QueryType.net)
        self.__queries.append(query)

    def aggregate_hosts(self):
        """
        Aggregate hosts from Censys, Shodan and ZoomEye.
        :return: None
        """
        # step 1: read queries from file, get the queries
        self.__read_queries()

        # step 2: initialize query list for aggregator
        censys_aggregator = CensysAggregator()
        censys_aggregator.set_queries(self.__queries)
        shodan_aggregator = ShodanAggregator()
        shodan_aggregator.set_queries(self.__queries)
        zoom_eye_aggregator = ZoomEyeAggregator()
        zoom_eye_aggregator.set_queries(self.__queries)

        # step 3: fetch all
        # censys_res = censys_aggregator.fetch_all()
        with open('censys.txt', 'r') as f:
            censys_res = json.loads(f.read())
        # with open('censys.txt', 'w') as f:
        #     f.write(json.dumps(censys_res))
        print('censys done.')
        # shodan_res = shodan_aggregator.fetch_all()
        with open('shodan.txt', 'r') as f:
            shodan_res = json.loads(f.read())
        # with open('shodan.txt', 'w') as f:
        #     f.write(json.dumps(shodan_res))
        print('shodan done.')
        # zoom_eye_res = zoom_eye_aggregator.fetch_all()
        with open('zoomeye.txt', 'r') as f:
            zoom_eye_res = json.loads(f.read())
        # with open('zoomeye.txt', 'w') as f:
        #     f.write(json.dumps(zoom_eye_res))
        print('zoomeye done.')

        # step 4: merge
        merged_res = AggregatorController.__merge(censys_res, shodan_res, zoom_eye_res)
        print('merging done.')

        # step 5: save to database
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
        merged = AggregatorController.__merge_res(censys_res, shodan_res, zoom_eye_res)

        # postprocess
        for query in merged:
            for host in merged[query]:
                index = merged[query].index(host)
                # TODO: now in 'data'
                if 'metadata.os' in host:
                    host['os'] = host['metadata.os']
                    host.pop('metadata.os')
                # Mongodb can only handle up to 64-bits int
                if 'ssl' in host and 'cert' in host['ssl'] and 'serial' in host['ssl']['cert']:
                    host['ssl']['cert']['serial'] = str(host['ssl']['cert']['serial'])
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
            with open('mid.txt', 'w') as f:
                f.write(json.dumps(mid_merged_res))
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
                if len(shodan_additional) > 0:  # new information from Shodan
                    shodan_additional.pop('ip')
                    shodan_additional.pop('ip_str')
                    source_saved = zoom_eye_host['source']  # in order not to be covered by merging dict
                    zoom_eye_host = dict({**zoom_eye_host, **shodan_additional})
                    zoom_eye_host['source'] = source_saved + '/Shodan'
                merged_res[query].append(zoom_eye_host)
        return merged_res

    def __read_cves(self):
        # TODO: read from file and database
        self.__cves = CVEAggregator.get_cve_by_years([2018])

    def aggregate_cve_details(self):
        """
        Aggregate threats from www.cvedetails.com. Incremental Update.
        :return: None
        """
        # step 1: read CVE range from file and find the difference between data in the local database and the Internet
        # And then initialize the aggregation queries
        self.__read_cves()
        print('total: ' + str(len(self.__cves)))
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
                    current, cves = cves[:CVE_BUFFER_SIZE], cves[CVE_BUFFER_SIZE:]
                finally:
                    lock.release()
                cve_aggregator = CVEAggregator()
                cve_aggregator.set_cves(current)
                res = cve_aggregator.update_cves()
                # step 3: save to database
                MongoHelper.save_cves(res)
                lock.acquire()
                try:
                    done += len(current)
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
    import json
    controller = AggregatorController()
    # controller.aggregate_hosts()
    controller.aggregate_cve_details()
