import shodan
from src.aggregate.aggregator import Aggregator, AggregatorTask
from src.aggregate.aggregator_task import AggregatorTaskType

API_KEY = 'LGFnk76Jfp3xzgG4u5VI9p3MD4AwMHmI'
PAGE_MAX = 100


class ShodanAggregator(Aggregator):

    def fetch_data(self, task):
        first_page_res = self.__fetch_page(task, 1)
        if len(first_page_res) != 0:
            all_data = first_page_res['matches']
            pages = int(first_page_res['total'] / PAGE_MAX) + 1 if first_page_res['total'] % PAGE_MAX != 0 else 0
            for page_num in range(2, pages + 1):
                res = self.__fetch_page(task, page_num)
                all_data += res['matches']
            for data in all_data:
                data['source'] = 'Shodan'
            return all_data
        else:
            return first_page_res

    @staticmethod
    def __fetch_page(task: AggregatorTask, page_num):
        """
        Fetch data on a single page
        :param task: AggregatorTask
        :param page_num: the number of the page, one indexed
        :return: raw data for the result (with metadata)
        """
        api = shodan.Shodan(API_KEY)
        try:
            if task.task_type == AggregatorTaskType.hostname:
                res = api.search(task.query, page=page_num)
            elif task.task_type == AggregatorTaskType.ip:
                res = api.search('ip:' + task.query, page=page_num)
            elif task.task_type == AggregatorTaskType.net:
                res = api.search('net:' + task.query, page=page_num)
            else:
                res = dict()  # default: no results
            return res
        except shodan.APIError as e:
            print('Error: %s', e)

    @staticmethod
    def get_info_by_ip(ip):
        """
        Only return the latest information of the specified ip address.
        :param ip: ip address.
        :return: the latest information.
        """
        api = shodan.Shodan(API_KEY)
        try:
            res = api.search('ip:' + ip, page=1)
            if len(res['matches']) == 0:
                return dict()
            elif len(res['matches']) == 1:
                return res['matches'][0]
            else:  # more than one result
                return ShodanAggregator.get_latest(res['matches'])
        except shodan.APIError as e:
            print('Error: %s', e)

    @staticmethod
    def get_latest(res: list):
        """
        Get the latest information of an ip address among multiple shodan search results.
        :param res: a list of shodan search results.
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
    # aggregator = ShodanAggregator()
    # _task = AggregatorTask('166.111.0.0/19', AggregatorTaskType.net)
    # aggregator.add_task(_task)
    # with open('1.txt', 'w') as f:
    #     f.write(json.dumps(aggregator.fetch_all()))
    print(json.dumps(ShodanAggregator.get_info_by_ip('106.120.133.38')))
