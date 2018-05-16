import requests
import sys
from src.aggregate.aggregator import Aggregator, AggregatorTask
from src.aggregate.aggregator_task import AggregatorTaskType

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

    def fetch_data(self, task: AggregatorTask):
        first_page_res = self.__fetch_page(task, 1)
        pages = int(first_page_res['available'] / PAGE_MAX) + 1 if first_page_res['available'] % PAGE_MAX != 0 else 0
        all_data = first_page_res['matches']
        for page_num in range(2, pages + 1):  # page_num: 2, 3, ..., pages
            res = self.__fetch_page(task, page_num)
            all_data += res['matches']
        for data in all_data:
            data['resource'] = 'ZoomEye'
        return all_data

    @staticmethod
    def __fetch_page(task: AggregatorTask, page_num):
        """
        Fetch data on a single page
        :param task: AggregatorTask
        :param page_num: the number of the page, one indexed
        :return: raw data for the result (with metadata)
        """
        token = ZoomEyeAggregator.__get_token()
        res = requests.get(API_URL + '/web/search', params=(('query', task.query), ('page', page_num)),
                           headers={'Authorization': 'JWT ' + token})
        if res.status_code != 200:
            print("error occurred: %s" % res.json()["error"])
            sys.exit(1)
        else:
            return res.json()

    @staticmethod
    def get_apps(ip):
        token = ZoomEyeAggregator.__get_token()
        res = requests.get(API_URL + '/web/search', params=(('query', ip), ('page', 1)),
                           headers={'Authorization': 'JWT ' + token})
        if res.status_code != 200:
            print("error occurred: %s" % res.json()["error"])
            sys.exit(1)
        else:
            if res.json()['total'] == 0:
                return list()
            else:
                return res.json()['matches'][0]


if __name__ == '__main__':
    import json

    aggregator = ZoomEyeAggregator()
    _task = AggregatorTask('tsinghua.edu.cn', AggregatorTaskType.hostname)
    aggregator.add_task(_task)
    print(json.dumps(aggregator.fetch_all()))
    # with open('1.txt', 'w') as f:
    #     f.write(json.dumps(aggregator.fetch_all()))
    # print(json.dumps(aggregator.get_apps('166.111.4.98')))
