from src.aggregate.censys import CensysAggregator
from src.aggregate.aggregator_task import AggregatorTaskType, AggregatorTask

if __name__ == '__main__':
    fields = ["ip", "protocols", "location.country"]
    task1 = AggregatorTask(AggregatorTaskType.keyword, 'hrh14', 'tsinghua.edu.cn', fields)
    # task2 = AggregatorTask(AggregatorTaskType.hosts, 'huangruihao', '23.0.0.0/8', fields)
    censys_aggregator = CensysAggregator()
    censys_aggregator.set_tasks([task1])
    print(censys_aggregator.fetch_all_data())
