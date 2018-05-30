from pymongo import MongoClient

DB_HOST = '127.0.0.1'
DB_PORT = 27017

DB_NAME = 'threats_db'
HOSTS_COLLECTION = 'hosts_collection'
CVES_COLLECTION = 'cves_collection'
THREATS_COLLECTION = 'threats_collection'


class MongoHelper:

    def __init__(self):
        pass

    @staticmethod
    def save_hosts(hosts):
        """
        Save the merged hosts data into database.
        :param hosts: the merged data.
        Format: {query0: [{field0: data0, field1: data1, ...}, {...}], query1: ...}
        :return: None
        """
        client = MongoClient(DB_HOST, DB_PORT)
        db = client[DB_NAME]
        collection = db[HOSTS_COLLECTION]
        # change format to: [{'query': query0, field0: data0, ...}, {...}]
        # Important: did not merge same hosts from different queries
        reformatted_hosts = list()
        for query in hosts:
            for host in hosts[query]:
                host['query'] = query
                reformatted_hosts.append(host)
        collection.insert_many(reformatted_hosts)
        client.close()

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
        Format: [{'name': name0, 'port': [port0, port1, ...], 'apps': [{'Type': Type, 'Vendor': Vendor,
        'Product': Product, 'Version': Version}, ...]}, {...}, ...]
        :return: None
        """
        client = MongoClient(DB_HOST, DB_PORT)
        db = client[DB_NAME]
        collection = db[CVES_COLLECTION]
        # format: [{'name': name0, 'ports': [port0, ...], 'apps': [...]}, {...}]
        collection.insert_many(cves)
        client.close()

    @staticmethod
    def read_cve_by_year(year):
        """
        Read CVE data including port and apps information by its year.
        :param year: the year.
        :return: an iterable mongodb cursor
        Format: [{'_id': ObjectId0, 'name': name0, 'ports': [...], 'apps': [...]}, {...}]
        """
        client = MongoClient(DB_HOST, DB_PORT)
        db = client[DB_NAME]
        collection = db[CVES_COLLECTION]
        import re
        regex = re.compile('CVE-' + str(year) + '-\d{4}')
        res = collection.find({'name': regex})
        client.close()
        return res


if __name__ == '__main__':
    # res = MongoHelper.read_cve_by_year(1999)
    # for r in res:
    #     print(r['name'])
    # print(res.count())
    pass
