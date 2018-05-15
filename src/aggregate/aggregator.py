from abc import ABC, abstractmethod
from src.aggregate.aggregator_task import AggregatorTask


class Aggregator(ABC):
    """
    The base class for aggregator. Each data source inherit a new class that overload the abstract methods.
    It fetch all the data required for all the users. The class only fetch data but do not deal with them.
    """

    def __init__(self):
        self.__tasks = list()  # no task

    def set_tasks(self, tasks):
        self.__tasks = list(set(tasks))

    def add_task(self, task: AggregatorTask):
        if task not in self.__tasks:
            self.__tasks.append(task)

    def remove_task(self, task: AggregatorTask):
        try:
            self.__tasks.remove(task)
        except ValueError as e:
            print(e)

    def clear_tasks(self):
        self.__tasks = list()

    def get_tasks(self):
        return self.__tasks

    def fetch_all(self):
        """
        Get all the data with the specified tasks.
        :return: a dict of data.
        Format: {query0: [{field0: data0, field1: data1, ...}, {...}], query1: ...}
        The dealing of this data should be done by the controller file (controller.py), such as saving to
        database, or doing some further analysis
        """
        all_data = dict()
        for task in self.__tasks:  # type: AggregatorTask
            all_data[task.query] = self.fetch_data(task)
        return all_data

    @abstractmethod
    def fetch_data(self, task):
        """
        Fetch data for a single task. To avoid Python's name mangling, the method is public.
        Actually, controller is not going to call this method.
        :param task: the task, type: AggregatorTask
        :return: a list of data.
        Format: [{field0: data0, field1: data1, ...}, {...}]
        """
        pass
