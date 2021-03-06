import requests
import sys
from src.aggregate.aggregator import Aggregator, Query
from src.aggregate.query import QueryType

PAGE_MAX = 20

API_URL = 'https://api.zoomeye.org'


class ZoomEyeAggregator(Aggregator):

    @staticmethod
    def __get_token():
        data = '{' \
               '"username": "huangruihaocst@126.com",' \
               '"password": "hrh?+fake1996"' \
               '}'
        res = requests.post(API_URL + '/user/login', data=data)
        if res.status_code != 200:
            print("error occurred: %s" % res.json()["error"])
            sys.exit(1)
        else:
            return res.json()['access_token']

    def fetch_data(self, query: Query):
        first_page_res = self.__fetch_page(query, 1)
        pages = int(first_page_res['available'] / PAGE_MAX) + 1 if first_page_res['available'] % PAGE_MAX != 0 else 0
        all_data = first_page_res['matches']
        for page_num in range(2, pages + 1):  # page_num: 2, 3, ..., pages
            res = self.__fetch_page(query, page_num)
            all_data += res['matches']
        for data in all_data:
            data['source'] = 'ZoomEye'
        return all_data

    @staticmethod
    def __fetch_page(query: Query, page_num):
        """
        Fetch data on a single page
        :param query: Query
        :param page_num: the number of the page, one indexed
        :return: raw data for the result (with metadata)
        """
        token = ZoomEyeAggregator.__get_token()
        res = requests.get(API_URL + '/web/search', params=(('query', query.query), ('page', page_num)),
                           headers={'Authorization': 'JWT ' + token})
        if res.status_code != 200:
            print("error occurred: %s" % res.json()["error"])
            sys.exit(1)
        else:
            return res.json()

    @staticmethod
    def get_info_by_ip(ip):
        token = ZoomEyeAggregator.__get_token()
        res = requests.get(API_URL + '/web/search', params=(('query', ip), ('page', 1)),
                           headers={'Authorization': 'JWT ' + token})
        if res.status_code != 200:
            print("error occurred: %s" % res.json()["error"])
            sys.exit(1)
        else:
            if res.json()['available'] == 0:
                return dict()
            elif res.json()['available'] == 1:
                return res.json()['matches'][0]
            else:
                return ZoomEyeAggregator.get_latest(res.json()['matches'])

    @staticmethod
    def get_latest(res: list):
        """
        Get the latest information of an ip address among multiple ZoomEye search results.
        :param res: a list of ZoomEye search results.
        :return: the latest information.
        """
        latest = res[0]
        from datetime import datetime
        fmt = '%Y-%m-%dT%H:%M:%S.%f'
        t = datetime.strptime(latest['timestamp'], fmt)
        for info in res:
            if datetime.strptime(info['timestamp'], fmt) > t:
                latest = info
                t = datetime.strptime(latest['timestamp'], fmt)
        return latest


if __name__ == '__main__':
    import json

    aggregator = ZoomEyeAggregator()
    _query = Query('tsinghua.edu.cn', QueryType.hostname)
    aggregator.add_query(_query)
    print(json.dumps(aggregator.fetch_all()))
