from abc import ABC, abstractmethod
from src.aggregate.query import Query


class Aggregator(ABC):
    """
    The base class for aggregator. Each data source inherit a new class that overload the abstract methods.
    It fetch all the data required for all the users. The class only fetch data but do not deal with them.
    """

    def __init__(self):
        self.__queries = list()  # no query

    def set_queries(self, queries):
        self.__queries = list(set(queries))

    def add_query(self, query: Query):
        if query not in self.__queries:
            self.__queries.append(query)

    def remove_query(self, query: Query):
        try:
            self.__queries.remove(query)
        except ValueError as e:
            print(e)

    def clear_queries(self):
        self.__queries = list()

    def get_queries(self):
        return self.__queries

    def fetch_all(self):
        """
        Get all the data with the specified queries.
        :return: a dict of data.
        Format: {query0: [{field0: data0, field1: data1, ...}, {...}], query1: ...}
        The dealing of this data should be done by the controller file (controller.py), such as saving to
        database, or doing some further analysis
        """
        all_data = dict()
        for query in self.__queries:  # type: Query
            all_data[query.query] = self.fetch_data(query)
        return all_data

    @abstractmethod
    def fetch_data(self, query):
        """
        Fetch data for a single query. To avoid Python's name mangling, the method is public.
        Actually, controller is not going to call this method.
        :param query: the query, type: Query
        :return: a list of data.
        Format: [{field0: data0, field1: data1, ...}, {...}]
        """
        pass
