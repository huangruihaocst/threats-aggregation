import requests
from src.aggregate.aggregator import Aggregator, AggregatorTask
from src.aggregate.aggregator_task import AggregatorTaskType

ACCESS_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZGVudGl0eSI6Imh1YW5ncnVpaGFvY3N0QDEyNi5jb20iLCJpYXQiOjE1Mj' \
               'Q1NzgzMzgsIm5iZiI6MTUyNDU3ODMzOCwiZXhwIjoxNTI0NjIxNTM4fQ.aFwucWsnUUg3nbuEPp3IK5HOGgPlQnxGokH215qguKI'


class ZoomEyeAggregator(Aggregator):

    def fetch_data(self, task):
        pass


if __name__ == '__main__':
    import json

    aggregator = ZoomEyeAggregator()
    _task = AggregatorTask('166.111.14.196', AggregatorTaskType.ip)
    aggregator.add_task(_task)
    print(json.dumps(aggregator.fetch_all()))
    # with open('1.txt', 'w') as f:
    #     f.write(json.dumps(aggregator.fetch_all()))
