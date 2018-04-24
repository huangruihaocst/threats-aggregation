from pymongo import MongoClient

DATABASE_HOST = '127.0.0.1'
DATABASE_PORT = 27017


class MongoHelper:

    def __init__(self):
        pass

    def save_all_res(self, all_res):
        """
        Save the result for tasks for all the users into database.
        :param all_res: the result for tasks for all the users into database.
        The return value of Aggregator.fetch_all_data().
        :return: the change of the data. The difference between the data newly fetched and
        the old data from the database.
        Format: {user0: changes0, user1: changes1, ...}
        """
        pass

    def __save_user_res(self, user_res):
        pass


if __name__ == '__main__':
    client = MongoClient(DATABASE_HOST, DATABASE_PORT)
    db = client['myDb']
    collection = db['hostsCollection']
    host = {'ip': '127.0.0.1', 'country': 'China', 'protocol': ['80/http', '443/https']}
    collection.insert_one(host)
    host = {'ip': '8.8.8.8', 'country': 'America', 'protocol': ['25/smtp']}
    collection.insert_one(host)
    print(collection.find_one({'ip': '127.0.0.1'}))
    client.close()

