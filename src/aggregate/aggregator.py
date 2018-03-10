from abc import ABC, abstractmethod


class Aggregator(ABC):
    """
    The base class for aggregator. Each data source inherit a new class that overload the abstract methods.
    It fetch all the data required for all the users.
    The class only fetch data but do not deal with them.
    """

    def __init__(self, fields: list, users: list):
        self.__fields = list(set(fields))
        self.__users = list(set(users))
        pass

    def add_field(self, field):
        if field not in self.__fields:  # fields should not contain identical fields
            self.__fields.append(field)

    def remove_field(self, field):
        try:
            self.__fields.remove(field)
        except ValueError as e:
            print(e)

    def set_fields(self, fields):
        self.__fields = list(set(fields))

    def get_fields(self):
        return self.__fields

    def add_user(self, user):
        if user not in self.__users:  # users should not contain identical users
            self.__users.append(user)

    def remove_user(self, user):
        try:
            self.__users.remove(user)
        except ValueError as e:
            print(e)

    def set_users(self, users):
        self.__users = list(set(users))

    def get_users(self):
        return self.__users

    def fetch_all_data(self):
        """
        Get all the data with the specified fields for all the users
        :return: a dict of data
        format: {user0: {result0: {field0: data0, field1: data1, ...}, result1: ...}, user1: ...}
        The dealing of this data should be done by the controller file (main.py), such as saving to database,
        or doing some further analysis
        """
        all_data = dict()
        for user in self.__users:
            all_data[user] = self.__fetch_data(user)
        return all_data

    @abstractmethod
    def __fetch_data(self, user):
        """
        Fetch data for a single user.
        :param user: the username
        :return: a dict of data
        format: {result0: {field0: data0, field1: data1, ...}}
        """
        pass
