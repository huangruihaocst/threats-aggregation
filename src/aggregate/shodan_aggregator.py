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
            if first_page_res['total'] > PAGE_MAX:
                # pages = int(first_page_res['total'] / PAGE_MAX) + 1
                # for page_num in range(2, pages + 1):
                #     res = self.__fetch_page(task, page_num)
                #     all_data += res['matches']
                # TODO: check the code here (if total > 100)
                pass
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
            if task.task_type == AggregatorTaskType.hostname or AggregatorTaskType.ip:
                res = api.search(task.query, page=page_num)
            elif task.task_type == AggregatorTaskType.net:
                res = api.search('net:' + task.query, page=page_num)
            else:
                res = dict()  # default: no results
            return res
        except shodan.APIError as e:
            print('Error: %s', e)


if __name__ == '__main__':
    import json
    aggregator = ShodanAggregator()
    _task = AggregatorTask('166.111.14.196', AggregatorTaskType.ip)
    aggregator.add_task(_task)
    with open('1.txt', 'w') as f:
        f.write(json.dumps(aggregator.fetch_all()))
