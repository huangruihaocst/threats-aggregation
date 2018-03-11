import sqlite3

DATABASE_ROUTE = '../../database/'


class DatabaseHelper:

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
    conn = sqlite3.connect(DATABASE_ROUTE + 'data.db')
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE IF NOT EXISTS hosts '
                   '(ip VARCHAR(15) PRIMARY KEY, '
                   'country VARCHAR(20), '
                   'protocols VARCHAR(100))')
    cursor.execute('INSERT INTO hosts (ip, country, protocols) VALUES '
                   '(\'101.6.32.201\', '
                   '\'China\', '
                   '\'[443/https, 80/http]\')')
    cursor.close()
    conn.commit()
    conn.close()
