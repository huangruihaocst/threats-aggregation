from enum import Enum


class AggregatorTaskType(Enum):
    auto = -1
    error = 0
    keyword = 1  # example: 'tsinghua.edu.cn'
    net = 2  # example: '166.111.0.0/16' (CIDR)
    ip = 3  # example: 166.111.14.196


class AggregatorTask:
    """
    Container.
    A messenger between aggregator controller and actual aggregator.
    Controller assign tasks for aggregator and aggregator does not know the actual relationship between
    user and its task. Only the controller reads the database and finds the relationship between
    users and tasks. Only query and type are common things among actual aggregators.
    """

    def __init__(self, query, task_type: AggregatorTaskType = AggregatorTaskType.auto):
        self.task_type = task_type
        self.query = query  # keyword or net

        if self.task_type == AggregatorTaskType.auto:
            # TODO: automatically decide the type of the query and report error if it is an illegal query
            pass
