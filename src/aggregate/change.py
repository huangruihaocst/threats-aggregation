from enum import Enum


class ChangeType(Enum):
    default = 0
    new_host = 1
    information_change = 2
    vulnerable = 3


class Change:
    """
    The container of the difference between the old host information and the new host information.
    It only holds one difference of a single host. All differences of a query should be presented in a list.
    """
    def __init__(self):
        self.change_type = ChangeType()
