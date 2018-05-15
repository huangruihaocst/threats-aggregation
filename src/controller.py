from src.aggregate.censys_aggregator import CensysAggregator
from src.aggregate.aggregator_task import AggregatorTaskType, AggregatorTask


class AggregatorController:
    """
    The class controls the process of aggregating threats and details of CVEs.
    """

    def __init__(self):
        pass

    def start_aggregate(self):
        """
        Start aggregation. The actual aggregation is done once in a well (maybe once a day).
        The thorough CVE details aggregator is called in a much longer cycle (maybe once a week).
        It must be run in a different thread.
        :return: None
        """
        pass

    @staticmethod
    def aggregate_threats():
        """
        Aggregate threats from Censys, Shodan and ZoomEye.
        :return: None
        """
        # step 1: read tasks from file, get the queries
        tasks = list()
        # step 2: use aggregators to fetch data from the Internet
        censys_aggregator = CensysAggregator()
        censys_aggregator.set_tasks(tasks)

        # step 3: save them into database

        pass

    @staticmethod
    def aggregate_cve_details():
        """
        Aggregate threats from www.cvedetails.com. Incremental Update.
        :return: None
        """
        pass


if __name__ == '__main__':
    pass
