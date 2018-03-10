from enum import Enum


class AggregatorTaskType(Enum):
    # only supports single rule now
    # TODO: allow users to add or remove hosts
    keyword = 1  # example: 'tsinghua.edu.cn'
    hosts = 2  # example: '23.0.0.0/8'


class AggregatorTask:
    """
    Container without method.
    A messenger between aggregator controller and actual aggregator.
    Controller assign tasks for aggregator and aggregator does not know the actual relationship between
    user and its task. Only the controller reads the database and find the relationship between user and tasks.
    """

    def __init__(self, task_type: AggregatorTaskType, user: str, task, fields: list):
        self.task_type = task_type
        self.user = user
        self.task = task  # keyword or hosts
        self.fields = fields
