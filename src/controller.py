from src.aggregate.censys_aggregator import CensysAggregator
from src.aggregate.shodan_aggregator import ShodanAggregator
from src.aggregate.zoomeye_aggregator import ZoomEyeAggregator
from src.cve_details.cve_details_aggregator import CVEAggregator
from src.aggregate.aggregator_task import AggregatorTaskType, AggregatorTask
from src.utils.mongo_helper import MongoHelper
from threading import Thread, Lock, current_thread

CVE_BUFFER_SIZE = 100
THREADS = 8


class AggregatorController:
    """
    The class controls the process of aggregating threats and details of CVEs.
    """

    def __init__(self):
        pass

    @staticmethod
    def start_aggregate():
        """
        Start aggregation. The actual aggregation is done once in a well.
        It must be run in a different thread.
        :return: None
        """
        AggregatorController.aggregate_threats()
        AggregatorController.aggregate_cve_details()
        AggregatorController.analyze()

    @staticmethod
    def analyze():
        """
        Use threats data and CVE data to analyze which hosts are vulnerability.
        Save the result into database.
        :return: None
        """
        pass

    @staticmethod
    def aggregate_threats():
        """
        Aggregate threats from Censys, Shodan and ZoomEye.
        :return: None
        """
        # step 1: read tasks from file, get the queries
        # TODO: read from file
        tasks = [AggregatorTask('tsinghua.edu.cn', AggregatorTaskType.hostname)]
        # step 2: initialize task list for aggregator
        censys_aggregator = CensysAggregator()
        censys_aggregator.set_tasks(tasks)
        shodan_aggregator = ShodanAggregator()
        shodan_aggregator.set_tasks(tasks)
        zoom_eye_aggregator = ZoomEyeAggregator()
        zoom_eye_aggregator.set_tasks(tasks)
        # step 3: fetch all
        censys_res = censys_aggregator.fetch_all()
        shodan_res = shodan_aggregator.fetch_all()
        zoom_eye_res = zoom_eye_aggregator.fetch_all()
        # step 4: merge
        # merged_res = self.merge(censys_res, shodan_res, zoom_eye_res)
        merged_res = AggregatorController.fake_merge(censys_res, shodan_res, zoom_eye_res)
        # step 5: save to database
        return merged_res

    @staticmethod
    def merge(censys_res, shodan_res, zoom_eye_res):
        """
        Merge host information from different sources and attach apps information to each host.
        The method is source sensitive. Adding new source requires rewriting of this method.
        :return: a merged dict.
        Format: {query0: [{field0: data0, field1: data1, ...}, {...}], query1: ...}
        """
        assert censys_res.keys() == shodan_res.keys() == zoom_eye_res.keys()
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
                    merged = dict({**merged, **zoom_eye_latest})
                    merged['source'] = merged['source'] + '/ZoomEye'
                    merged_res[query].append(merged)
                    zoom_eye = [zoom_eye_host for zoom_eye_host in zoom_eye if zoom_eye_host not in zoom_eye_corr]
                else:  # no corresponding in ZoomEye
                    zoom_eye_additional = ZoomEyeAggregator.get_info_by_ip(merged['ip'])
                    if len(zoom_eye_additional) > 0:  # new information from ZoomEye
                        zoom_eye_additional.pop('ip')
                        zoom_eye_additional.pop('geoinfo')
                        merged = dict({**merged, **zoom_eye_additional})
                        merged['source'] = merged['source'] + '/ZoomEye'
                    merged_res[query].append(merged)
            for zoom_eye_host in zoom_eye:  # no corresponding in merged
                zoom_eye_host['ip'] = zoom_eye_host['ip'][0]
                zoom_eye_host.pop('geoinfo')
                censys_additional = CensysAggregator.get_info_by_ip(zoom_eye_host['ip'])
                if len(censys_additional) > 0:  # new information from Censys
                    censys_additional.pop('ip')
                    zoom_eye_host = dict({**zoom_eye_host, **censys_additional})
                    zoom_eye_host['source'] = zoom_eye_host['source'] + '/Censys'
                shodan_additional = ShodanAggregator.get_info_by_ip(zoom_eye_host['ip'])
                if len(shodan_additional) > 0:  # new information from Shodan
                    shodan_additional.pop('ip')
                    shodan_additional.pop('ip_str')
                    zoom_eye_host = dict({**zoom_eye_host, **shodan_additional})
                    zoom_eye_host['source'] = zoom_eye_host['source'] + '/Shodan'
                merged_res[query].append(zoom_eye_host)
        return merged_res

    @staticmethod
    def merge_from_json(nested_json):
        """
        Test method.
        :return:
        """
        all_data = json.loads(nested_json)
        censys_res = all_data['censys']
        shodan_res = all_data['shodan']
        zoom_eye_res = all_data['zoom_eye']
        return AggregatorController.merge(censys_res, shodan_res, zoom_eye_res)

    @staticmethod
    def fake_merge(censys_res, shodan_res, zoom_eye_res):
        all_data = dict()
        all_data['censys'] = censys_res
        all_data['shodan'] = shodan_res
        all_data['zoom_eye'] = zoom_eye_res
        return all_data

    @staticmethod
    def aggregate_cve_details():
        """
        Aggregate threats from www.cvedetails.com. Incremental Update.
        :return: None
        """
        # step 1: read CVE range from file and find the difference between data in the local database and the Internet
        # And then initialize the aggregation task
        # TODO: read from file and database
        # cves = CVEAggregator.get_cve_by_years([2018])
        import json
        with open('cve_details/1.txt', 'r') as f:
            cves = json.loads(f.read())
        print('total: ' + str(len(cves)))
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
                mongo = MongoHelper()
                mongo.save_cves(res)
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
    controller.aggregate_cve_details()
    # with open('1.txt', 'r') as f:
    #     nested_json = f.read()
    #     # print(json.dumps(controller.merge_from_json(nested_json)))
    #     with open('2.txt', 'w') as f2:
    #         f2.write(json.dumps(controller.merge_from_json(nested_json)))
    # with open('1.txt', 'w') as f:
    #     f.write(json.dumps(controller.aggregate_threats()))
    # with open('3.txt', 'w') as f:
    #     f.write(json.dumps(AggregatorController.aggregate_cve_details()))
