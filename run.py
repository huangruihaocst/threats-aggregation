from flask import Flask, request
from flask import render_template

from src.utils.mongo_helper import MongoHelper
import json

app = Flask(__name__, static_url_path='/static')
CVE_COUNT = 3


@app.route('/index/<int:page_num>')
def index(page_num):
    threats = MongoHelper.read_threats(page_num - 1)  # change to 1 indexed
    pages = MongoHelper.get_threats_pages()
    for threat in threats:
        threat['original'] = MongoHelper.read_host_by_ip_and_query(threat['ip'], threat['query'])
        threat['original']['protocols'] = list()
        if 'data' in threat['original']:
            for data in threat['original']['data']:
                found = False
                for key in data:
                    if isinstance(data[key], dict) and key not in ['location', '_shodan', 'opts', 'vulns']:
                        threat['original']['protocols'].append(str(data['port']) + '/' + key)
                        found = True
                if not found:
                    threat['original']['protocols'].append(str(data['port']) + '/' + 'Unknown')
    for threat in threats:
        if len(threat['CVEs']) > CVE_COUNT:
            threat['over'] = True
        else:
            threat['over'] = False
        threat['CVEs'] = list(threat['CVEs'].keys())
        threat['CVEs'] = threat['CVEs'][:CVE_COUNT]
    with open('src/last_updated.txt', 'r') as f:
        last_updated = f.read()
    with open('src/config.json') as f:
        config = json.loads(f.read())
    queries = list()
    for query in config['queries']:
        queries.append(query['query'])
    return render_template('index.html', threats=threats, pages=pages, page_num=page_num, last_updated=last_updated,
                           queries=queries)


@app.route('/')
def root():
    return index(1)


@app.route('/details/<string:ip>')
def details(ip):
    threat = MongoHelper.read_threat(ip)
    if threat is None:
        return render_template('empty.html', title=ip)
    for cve in threat['CVEs']:
        if 'cvss' not in threat['CVEs'][cve] or 'summary' not in threat['CVEs'][cve]:
            cve_info = MongoHelper.read_cve_by_name(cve)
            threat['CVEs'][cve]['cvss'] = cve_info['cvss']
            threat['CVEs'][cve]['summary'] = cve_info['summary']
        if 'ports' in threat['CVEs'][cve] and len(threat['CVEs'][cve]['ports']) == 0:
            threat['CVEs'][cve].pop('ports')
        if 'apps' in threat['CVEs'][cve] and len(threat['CVEs'][cve]['apps']) == 0:
            threat['CVEs'][cve].pop('apps')
    original = MongoHelper.read_host_by_ip_and_query(ip, threat['query'])
    original.pop('_id')
    services = list()
    if 'data' in original:
        for data in original['data']:
            service = dict()
            service['raw'] = data
            found = False
            for key in data:
                if isinstance(data[key], dict) and key not in ['location', '_shodan', 'opts', 'vulns']:
                    service['protocol'] = key
                    found = True
            if not found:
                service['protocol'] = 'Unknown'
            services.append(service)
    return render_template('details.html', threat=threat, original=original, services=services)


@app.route('/search', methods=['POST'])
def search():
    keyword = request.form['search']
    # decide it is IP/CVE/Query
    import re
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', keyword):  # IP
        return details(keyword)
    elif re.match(r'^CVE-\d{4}-\d*$', keyword):  # CVE
        res = list(MongoHelper.read_threats_by_cve(keyword))
        if len(res) == 0:
            return render_template('empty.html', title=keyword)
        else:
            for threat in res:
                threat['original'] = MongoHelper.read_host_by_ip_and_query(threat['ip'], threat['query'])
                threat['original']['protocols'] = list()
                if 'data' in threat['original']:
                    for data in threat['original']['data']:
                        found = False
                        for key in data:
                            if isinstance(data[key], dict) and key not in ['location', '_shodan', 'opts', 'vulns']:
                                threat['original']['protocols'].append(str(data['port']) + '/' + key)
                                found = True
                        if not found:
                            threat['original']['protocols'].append(str(data['port']) + '/' + 'Unknown')
            return render_template('search.html', title=keyword, threats=res, type='CVE')
    else:  # Query
        res = list(MongoHelper.read_threats_by_query(keyword))
        if len(res) == 0:
            return render_template('empty.html', title=keyword)
        else:
            for threat in res:
                threat['original'] = MongoHelper.read_host_by_ip_and_query(threat['ip'], threat['query'])
                threat['original']['protocols'] = list()
                if 'data' in threat['original']:
                    for data in threat['original']['data']:
                        found = False
                        for key in data:
                            if isinstance(data[key], dict) and key not in ['location', '_shodan', 'opts', 'vulns']:
                                threat['original']['protocols'].append(str(data['port']) + '/' + key)
                                found = True
                        if not found:
                            threat['original']['protocols'].append(str(data['port']) + '/' + 'Unknown')
            return render_template('search.html', title=keyword, threats=res, type='Query')


@app.route('/raw/<string:ip>')
def raw(ip):
    ip = ip.split('&')[0]
    raw_data = MongoHelper.read_host_by_ip(ip)
    raw_data.pop('_id')
    return render_template('raw.html', ip=ip, raw=json.dumps(raw_data, indent=4, sort_keys=True))


if __name__ == '__main__':
    app.run()
