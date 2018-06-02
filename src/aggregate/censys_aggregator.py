import sys
import json
import requests
from src.aggregate.aggregator import Aggregator, Query
from src.aggregate.query import QueryType

API_URL = "https://censys.io/api/v1"
# UID = "97c34127-c350-45a6-81a2-7290b0a0f68d"
# SECRET = "aHSyRxEsdiaDYbeQzdOkssNBLFMVdNnm"

UID = 'a4ec2e6d-85c7-4bbd-8534-69d1f328f004'
SECRET = 'QoWszHM2phUHc60osVqafy4I4IiiEjYe'


class CensysAggregator(Aggregator):

    def fetch_data(self, query):
        first_page_res = self.__fetch_page(query, 1)
        pages = first_page_res['metadata']['pages']
        all_data = first_page_res['results']  # type: list
        for page_num in range(2, pages + 1):  # page_num: 2, 3, ..., pages
            res = self.__fetch_page(query, page_num)
            all_data += res['results']
        for data in all_data:
            data['source'] = 'Censys'
        return all_data

    @staticmethod
    def __fetch_page(query: Query, page_num):
        """
        Fetch data on a single page
        :param query: Query
        :param page_num: the number of the page, one indexed
        :return: raw data for the result (with metadata)
        """
        fields = ['ip', 'protocols', 'metadata.os', 'metadata.os_version', 'tags']
        data = {"query": query.query,
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
    # print(CensysAggregator.get_info_by_ip('166.111.176.55'))
    c = CensysAggregator()
    queries = [Query('166.111.0.0/21', QueryType.net)]
    c.set_queries(queries)
    print(json.dumps(c.fetch_all()))
