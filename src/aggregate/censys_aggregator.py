import sys
import json
import requests
from src.aggregate.aggregator import Aggregator, AggregatorTask
from src.aggregate.aggregator_task import AggregatorTaskType

API_URL = "https://censys.io/api/v1"
UID = "97c34127-c350-45a6-81a2-7290b0a0f68d"
SECRET = "aHSyRxEsdiaDYbeQzdOkssNBLFMVdNnm"


class CensysAggregator(Aggregator):

    def fetch_data(self, task):
        first_page_res = self.__fetch_page(task, 1)
        pages = first_page_res['metadata']['pages']
        all_data = first_page_res['results']  # type: list
        for page_num in range(2, pages + 1):  # page_num: 2, 3, ..., pages
            res = self.__fetch_page(task, page_num)
            all_data += res['results']
        for data in all_data:
            data['source'] = 'Censys'
        return all_data

    @staticmethod
    def __fetch_page(task: AggregatorTask, page_num):
        """
        Fetch data on a single page
        :param task: AggregatorTask
        :param page_num: the number of the page, one indexed
        :return: raw data for the result (with metadata)
        """
        fields = ['ip', 'protocols', 'metadata.os', 'metadata.os_version', 'tags']
        data = {"query": task.query,
                "page": page_num,
                "fields": fields}
        res = requests.post(API_URL + "/search/ipv4", data=json.dumps(data), auth=(UID, SECRET))
        if res.status_code != 200:
            print("error occurred: %s" % res.json()["error"])
            sys.exit(1)
        else:
            return res.json()

    @staticmethod
    def get_info_by_ip(ip):
        fields = ['ip', 'protocols', 'metadata.os', 'metadata.os_version', 'tags']
        data = {"query": ip,
                "page": 1,
                "fields": fields}
        res = requests.post(API_URL + "/search/ipv4", data=json.dumps(data), auth=(UID, SECRET))
        if res.status_code != 200:
            print("error occurred: %s" % res.json()["error"])
            sys.exit(1)
        else:
            if len(res.json()['results']) == 0:
                return dict()
            else:  # no redundant
                return res.json()['results'][0]


if __name__ == '__main__':
    # censys = CensysAggregator()
    # _task = AggregatorTask('tsinghua.edu.cn', AggregatorTaskType.hostname)
    # censys.add_task(_task)
    # print(censys.fetch_all())
    print(CensysAggregator.get_info_by_ip('166.111.4.40'))

