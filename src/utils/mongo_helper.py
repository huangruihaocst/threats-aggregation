from pymongo import MongoClient

DATABASE_HOST = '127.0.0.1'
DATABASE_PORT = 27017

DB_NAME = 'threats_db'
HOSTS_COLLECTION = 'hosts_collection'
CVES_COLLECTION = 'cves_collection'
THREATS_COLLECTION = 'threats_collection'


class MongoHelper:

    def __init__(self):
        pass

    @staticmethod
    def save_threats(threats):
        """
        Save the merged threats data into database.
        :param threats: the merged data.
        Format: {query0: [{field0: data0, field1: data1, ...}, {...}], query1: ...}
        :return: None
        """
        client = MongoClient(DATABASE_HOST, DATABASE_PORT)
        db = client[DB_NAME]
        collection = db[THREATS_COLLECTION]

        collection.insert_many(threats)
        client.close()
        pass

    def read_threat_by_ip(self, ip):
        """
        Read threat data of a host by its ip address.
        :param ip: ip address.
        :return: a dict of its information. Empty dict if the ip address does not exist.
        """
        pass

    @staticmethod
    def save_cves(cves: list):
        """
        Save CVE details into database.
        :param cves: a list of cve data.
        Format: {[{'name': name0, 'port': [port0, port1, ...], 'apps': [{'Type': Type, 'Vendor': Vendor,
        'Product': Product, 'Version': Version}, ...]}, {...}, ...]
        :return: None
        """
        client = MongoClient(DATABASE_HOST, DATABASE_PORT)
        db = client[DB_NAME]
        collection = db[CVES_COLLECTION]
        # format: [{'name': name0, 'ports': [port0, ...], 'apps': [...]}, {...}]
        collection.insert_many(cves)
        client.close()

    def read_cve_by_name(self, cve):
        """
        Read CVE data including port and apps information by its name.
        :param cve: the name of the CVE.
        :return: a dict of its information. Empty if the CVE does not exist.
        """
        pass


if __name__ == '__main__':
    pass

