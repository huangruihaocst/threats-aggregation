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
        :return: None
        """
        import datetime
        for query in self.__queries:  # each query
            # check if there are vulnerabilities by year
            for year in range(CVE_START_YEAR, datetime.datetime.now().year + 1):
                cves_cursor = MongoHelper.read_cves_by_year(year)
                for cve in cves_cursor:  # each CVE
                    hosts_cursor = MongoHelper.read_hosts_by_query(query)
                    for host in hosts_cursor:  # each host
                        if AggregatorController.__is_vulnerable(host, cve):
                            # save to database
                            pass

    @staticmethod
    def __is_vulnerable(host, cve):
        """
        Check if the host is vulnerable to the certain CVE.
        :param host: host information
        :param cve: CVE information
        :return: True if is vulnerable, otherwise False.
        """
        pass

    def __read_queries(self):
        # TODO: read queries from file
        query = Query('166.111.0.0/21', QueryType.net)
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
        censys_res = censys_aggregator.fetch_all()
        shodan_res = shodan_aggregator.fetch_all()
        zoom_eye_res = zoom_eye_aggregator.fetch_all()
        # step 4: merge
        merged_res = AggregatorController.__merge(censys_res, shodan_res, zoom_eye_res)
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
                shodan_corr = [shodan_host for shodan_host in shodan if shodan_host['ip_str'] == ip]
                if len(shodan_corr) > 0:  # same ip address in Censys and Shodan
                    shodan_latest = ShodanAggregator.get_latest(shodan_corr)  # find the latest information
                    merged = censys_host
                    shodan_latest.pop('ip')
                    shodan_latest.pop('ip_str')
                    shodan_latest.pop('source')
                    merged = dict({**merged, **shodan_latest})
                    if 'tags' in shodan_latest:
                        merged['tags'] = censys_host['tags'] + shodan_latest['tags']
                    merged['source'] = 'Censys/Shodan'
                    mid_merged_res.append(merged)
                    shodan = [shodan_host for shodan_host in shodan if shodan_host not in shodan_corr]
                else:  # no corresponding result in Shodan
                    shodan_additional = ShodanAggregator.get_info_by_ip(censys_host['ip'])
                    if len(shodan_additional) > 0:  # new information from Shodan
                        shodan_additional.pop('ip')
                        shodan_additional.pop('ip_str')
                        censys_host = dict({**censys_host, **shodan_additional})
                        censys_host['source'] = 'Censys/Shodan'
                    mid_merged_res.append(censys_host)
            for shodan_host in shodan:  # no corresponding in Censys
                shodan_host['ip'] = shodan_host['ip_str']
                shodan_host.pop('ip_str')
                censys_additional = CensysAggregator.get_info_by_ip(shodan_host['ip'])
                if len(censys_additional) > 0:  # new information from Censys
                    censys_additional.pop('ip')
                    shodan_host = dict({**shodan_host, **censys_additional})
                    shodan_host['source'] = 'Censys/Shodan'
                mid_merged_res.append(shodan_host)
            # step 2: merge censys+shodan and zoom_eye
            for merged in mid_merged_res:
                ip = merged['ip']
                zoom_eye_corr = [zoom_eye_host for zoom_eye_host in zoom_eye if zoom_eye_host['ip'][0] == ip]
                if len(zoom_eye_corr) > 0:  # same ip address in merged and ZoomEye
                    zoom_eye_latest = ZoomEyeAggregator.get_latest(zoom_eye_corr)
                    zoom_eye_latest.pop('ip')
                    zoom_eye_latest.pop('geoinfo')
                    source_saved = merged['source']  # in order not to be covered by merging dict
                    merged = dict({**merged, **zoom_eye_latest})
                    merged['source'] = source_saved + '/ZoomEye'
                    merged_res[query].append(merged)
                    zoom_eye = [zoom_eye_host for zoom_eye_host in zoom_eye if zoom_eye_host not in zoom_eye_corr]
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
                censys_additional = CensysAggregator.get_info_by_ip(zoom_eye_host['ip'])
                if len(censys_additional) > 0:  # new information from Censys
                    censys_additional.pop('ip')
                    source_saved = zoom_eye_host['source']  # in order not to be covered by merging dict
                    zoom_eye_host = dict({**zoom_eye_host, **censys_additional})
                    zoom_eye_host['source'] = source_saved + '/Censys'
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
    controller.aggregate_hosts()
    # with open('2.txt', 'w') as f:
    #     f.write(json.dumps(controller.aggregate_hosts()))
    # controller.aggregate_cve_details()
    # with open('4.txt', 'r') as f:
    #     d = json.loads(f.read())
    # d = {'http': {'html': '12345', 'components': {'animate.css': {'categories': ['Web']}}}}
    # d = remove_dots(d)
    # print(json.dumps(d))
