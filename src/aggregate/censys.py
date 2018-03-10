import sys
import json
import requests
from src.aggregate.aggregator import Aggregator

API_URL = "https://censys.io/api/v1"
UID = "97c34127-c350-45a6-81a2-7290b0a0f68d"
SECRET = "aHSyRxEsdiaDYbeQzdOkssNBLFMVdNnm"


class CensysAggregator(Aggregator):

    def fetch_data(self, task):
        first_page_res = self.__fetch_page(task, 1)
        pages = first_page_res['metadata']['pages']
        all_data = first_page_res['results']
        for page_number in range(2, pages + 1):  # page_number: 2, 3, ..., pages
            res = self.__fetch_page(task, page_number)
            all_data += res['results']  # change dict to list
        return all_data

    @staticmethod
    def __fetch_page(task, page_number):
        """
        Fetch data on a single page
        :param task: AggregatorTask
        :param page_number: the number of the page, one indexed
        :return: raw data for the result (with metadata)
        """
        data = {"query": task.task,
                "page": page_number,
                "fields": task.fields}
        res = requests.post(API_URL + "/search/ipv4", data=json.dumps(data), auth=(UID, SECRET))
        if res.status_code != 200:
            print("error occurred: %s" % res.json()["error"])
            sys.exit(1)
        else:
            return res.json()
