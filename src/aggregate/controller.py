from src.aggregate.censys_aggregator import CensysAggregator
from src.aggregate.aggregator_task import AggregatorTaskType, AggregatorTask


class AggregatorController:
    # Control the process

    def __init__(self):
        pass

    def start_aggregate(self):
        """
        Start aggregation. The actual aggregation is done once in a well (maybe once a day).
        It must be run in a different thread.
        :return: None
        """
        pass

    def aggregate(self):
        """
        The actual aggregation.
        :return: None
        """
        # step 1: read tasks from sqlite database, get the queries
        tasks = list()
        # step 2: use aggregators to fetch data from the Internet and save them to MongoDB
        censys_aggregator = CensysAggregator()
        censys_aggregator.set_tasks(tasks)

        # step 3: find the difference between the old data and the new data and return this value to its caller

        pass


if __name__ == '__main__':
    pass
