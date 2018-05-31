from enum import Enum


class QueryType(Enum):
    auto = -1
    error = 0
    hostname = 1  # example: 'tsinghua.edu.cn'
    net = 2  # example: '166.111.0.0/16' (CIDR)
    ip = 3  # example: 166.111.14.196


class Query:
    """
    Container.
    A messenger between aggregator controller and actual aggregator.
    """

    def __init__(self, query, query_type: QueryType = QueryType.auto):
        self.query_type = query_type
        self.query = query  # keyword or net

        if self.query_type == QueryType.auto:
            # TODO: automatically decide the type of the query and report error if it is an illegal query
            pass
