import shodan
from src.aggregate.aggregator import Aggregator, Query
from src.aggregate.query import QueryType

API_KEY = 'LGFnk76Jfp3xzgG4u5VI9p3MD4AwMHmI'
PAGE_MAX = 100
RETRY_TIMES = 15


class ShodanAggregator(Aggregator):

    def fetch_data(self, query):
        first_page_ip = ShodanAggregator.__fetch_page_ip(query, 1)
        if len(first_page_ip) > 0:
            all_ip = first_page_ip['matches']
            pages = int(first_page_ip['total'] / PAGE_MAX) + 1 if first_page_ip['total'] % PAGE_MAX != 0 else 0
            for page_num in range(2, pages + 1):
                res = ShodanAggregator.__fetch_page_ip(query, page_num)
                all_ip += res['matches']
            all_ip = list(set(all_ip))
            all_data = list()
            for ip in all_ip:
                data = ShodanAggregator.get_info_by_ip(ip)
                data['source'] = 'Shodan'
                all_data.append(data)
            return all_data
        else:
            return list()

    @staticmethod
    def __fetch_page_ip(query: Query, page_num):
        """
        Fetch the ip address on a single page
        :param query: Query
        :param page_num: the number of the page, one indexed
        :return: raw data for the result (with metadata)
        """
        api = shodan.Shodan(API_KEY)
        attempts = 0
        while attempts < RETRY_TIMES:
            try:
                res = dict()  # result
                res['matches'] = list()
                if query.query_type == QueryType.hostname:
                    response = api.search(query.query, page=page_num)
                elif query.query_type == QueryType.ip:
                    response = api.search('ip:' + query.query, page=page_num)
                elif query.query_type == QueryType.net:
                    response = api.search('net:' + query.query, page=page_num)
                else:
                    response = dict()  # default: no results
                res['total'] = response['total']
                for host in response['matches']:
                    res['matches'].append(host['ip_str'])
                return res
            except shodan.APIError as e:
                print('Error: ', e)
        # if failed times exceed RETRY_TIMES, return a default result
        return {'matches': list(), 'total': 0}

    @staticmethod
    def get_info_by_ip(ip):
        """
        Only return the latest information of the specified ip address.
        :param ip: ip address.
        :return: the latest information.
        None if no result for that ip.
        """
        api = shodan.Shodan(API_KEY)
        attempts = 0
        while attempts < RETRY_TIMES:
            try:
                res = api.host(ip)
                if len(res) > 0:
                    if 'ip_str' not in res:
                        res['ip_str'] = ip
                    if attempts > 0:
                        print(ip + ': succeeded by ' + str(attempts + 1) + ' attempts.')
                    return res
            except shodan.APIError as e:
                attempts += 1
                # print(ip + ' Error: ', e)
                import time
                time.sleep(1)  # to avoid 1 request/sec limit
        # if failed times exceed RETRY_TIMES, return a default result
        print(ip + ': failed fetching host information.')
        return {'ip_str': ip}

    @staticmethod
    def get_latest(res: list):
        """
        Get the latest information of an ip address among multiple Shodan search results.
        :param res: a list of Shodan search results.
        :return: the latest information.
        """
        latest = res[0]
        from datetime import datetime
        fmt = '%Y-%m-%dT%H:%M:%S.%f'
        t = datetime.strptime(latest['timestamp'], fmt)
        for info in res:
            if datetime.strptime(info['timestamp'], fmt) > t:
                latest = info
                t = datetime.strptime(latest['timestamp'], fmt)
        return latest


if __name__ == '__main__':
    import json
    print(json.dumps(ShodanAggregator.get_info_by_ip('166.111.53.174')))

