import requests
import sys
from src.aggregate.aggregator import Aggregator, AggregatorTask
from src.aggregate.aggregator_task import AggregatorTaskType

PAGE_MAX = 20

API_URL = 'https://api.zoomeye.org'
ACCESS_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZGVudGl0eSI6Imh1YW5ncnVpaGFvY3N0QDEyNi5jb20iLCJpYXQiOjE1MjYy' \
               'ODg1MDksIm5iZiI6MTUyNjI4ODUwOSwiZXhwIjoxNTI2MzMxNzA5fQ.9Gnc7Srqy0Tn9KYt5gbvmtLS4XvQgp2eaFK5qBlFNdY'


class ZoomEyeAggregator(Aggregator):

    def fetch_data(self, task: AggregatorTask):
        first_page_res = self.__fetch_page(task, 1)
        pages = int(first_page_res['available'] / PAGE_MAX) + 1
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
        res = requests.get(API_URL + '/host/search', params=(('query', task.query), ('page', page_num)),
                           headers={'Authorization': 'JWT ' + ACCESS_TOKEN})
        if res.status_code != 200:
            print("error occurred: %s" % res.json()["error"])
            sys.exit(1)
        else:
            return res.json()


if __name__ == '__main__':
    import json

    aggregator = ZoomEyeAggregator()
    _task = AggregatorTask('tsinghua.edu.cn', AggregatorTaskType.hostname)
    aggregator.add_task(_task)
    print(json.dumps(aggregator.fetch_all()))
