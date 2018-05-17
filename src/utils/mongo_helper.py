from pymongo import MongoClient

DATABASE_HOST = '127.0.0.1'
DATABASE_PORT = 27017


class MongoHelper:

    def __init__(self):
        pass

    def save_threats(self, threats):
        """
        Save the merged threats data into database.
        :param threats: the merged data.
        Format: {query0: [{field0: data0, field1: data1, ...}, {...}], query1: ...}
        :return: None
        """
        pass

    def read_threat_by_ip(self, ip):
        """
        Read threat data of a host by its ip address.
        :param ip: ip address.
        :return: a dict of its information. Empty dict if the ip address does not exist.
        """
        pass

    def save_cve(self, cves: list):
        """
        Save CVE details into database.
        :param cves: a list of cve data.
        Format: {'cve0': {'port': [port0, port1, ...], 'apps': [{'Type': Type, 'Vendor': Vendor, 'Product': Product,
         'Version': Version}, ...]}, 'cve1': ...}
        :return: None
        """
        pass

    def read_cve_by_name(self, cve):
        """
        Read CVE data including port and apps information by its name.
        :param cve: the name of the CVE.
        :return: a dict of its information. Empty if the CVE does not exist.
        """
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

