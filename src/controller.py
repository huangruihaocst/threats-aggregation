from src.aggregate.censys_aggregator import CensysAggregator
from src.aggregate.shodan_aggregator import ShodanAggregator
from src.aggregate.zoomeye_aggregator import ZoomEyeAggregator
from src.aggregate.aggregator_task import AggregatorTaskType, AggregatorTask
from src.utils.mongo_helper import MongoHelper


class AggregatorController:
    """
    The class controls the process of aggregating threats and details of CVEs.
    """

    def __init__(self):
        pass

    def start_aggregate(self):
        """
        Start aggregation. The actual aggregation is done once in a well (maybe once a day).
        The thorough CVE details aggregator is called in a much longer cycle (maybe once a week).
        It must be run in a different thread.
        :return: None
        """
        pass

    def aggregate_threats(self):
        """
        Aggregate threats from Censys, Shodan and ZoomEye.
        :return: None
        """
        # step 1: read tasks from file, get the queries
        tasks = [AggregatorTask('tsinghua.edu.cn', AggregatorTaskType.hostname)]
        # TODO: read from file
        # step 2: initialize task list for aggregator
        censys = CensysAggregator()
        censys.set_tasks(tasks)
        shodan = ShodanAggregator()
        shodan.set_tasks(tasks)
        zoom_eye = ZoomEyeAggregator()
        zoom_eye.set_tasks(tasks)
        # step 3: fetch all
        censys_res = censys.fetch_all()
        shodan_res = shodan.fetch_all()
        zoom_eye_res = zoom_eye.fetch_all()
        # step 4: merge
        # merged_res = self.merge(censys_res, shodan_res, zoom_eye_res)
        merged_res = self.fake_merge(censys_res, shodan_res, zoom_eye_res)
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
            merged_res[query] = list()
            # step 1: merge censys and shodan
            for censys_host in censys:
                ip = censys_host['ip']
                shodan_corr = [shodan_host for shodan_host in shodan if shodan_host['ip_str'] == ip]
                if len(shodan_corr) > 0:  # same ip address in censys and shodan
                    shodan_latest = ShodanAggregator.get_latest(shodan_corr)  # get the latest information
                    shodan_corr.remove(shodan_latest)
                    shodan = [shodan_host for shodan_host in shodan if shodan_host not in shodan_corr]
                    merged = censys_host
                    shodan_latest.pop('ip')
                    shodan_latest.pop('ip_str')
                    shodan_latest.pop('source')
                    merged = dict({**merged, **shodan_latest})
                    if 'tags' in shodan_latest:
                        merged['tags'] = censys_host['tags'] + shodan_latest['tags']
                    merged['source'] = 'Censys/Shodan'
                    merged_res[query].append(merged)
                    shodan.remove(shodan_latest)
                else:  # no corresponding result in shodan
                    shodan_additional = ShodanAggregator.get_info_by_ip(censys_host['ip'])
                    if len(shodan_additional) > 0:  # new information from shodan
                        shodan_additional.pop('ip')
                        shodan_additional.pop('ip_str')
                        censys_host = dict({**censys_host, **shodan_additional})
                        censys_host['source'] = 'Censys/Shodan'
                    merged_res[query].append(censys_host)
            for shodan_host in shodan:  # no corresponding in censys
                shodan_host['ip'] = shodan_host['ip_str']
                shodan_host.pop('ip_str')
                censys_additional = CensysAggregator.get_info_by_ip(shodan_host['ip'])['results']
                if len(censys_additional) > 0:  # new information from censys
                    censys_additional.pop('ip')
                    shodan_host = dict({**shodan_host, **censys_additional})
                    shodan_host['source'] = 'Censys/Shodan'
                merged_res[query].append(shodan_host)
            # step 2: merge censys+shodan and zoom_eye

            # step 3: remove redundant hosts
        return merged_res

    def merge_from_json(self, nested_json):
        """
        Test method.
        :return:
        """
        all_data = json.loads(nested_json)
        censys_res = all_data['censys']
        shodan_res = all_data['shodan']
        zoom_eye_res = all_data['zoom_eye']
        return self.merge(censys_res, shodan_res, zoom_eye_res)

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
        pass


if __name__ == '__main__':
    import json
    controller = AggregatorController()
    with open('1.txt', 'r') as f:
        nested_json = f.read()
        # print(json.dumps(controller.merge_from_json(nested_json)))
        with open('2.txt', 'w') as f2:
            f2.write(json.dumps(controller.merge_from_json(nested_json)))
