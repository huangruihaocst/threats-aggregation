from flask import Flask
from flask import render_template

from src.utils.mongo_helper import MongoHelper

app = Flask(__name__, static_url_path='/static')


@app.route('/index/<int:page_num>')
def root(page_num):
    threats = MongoHelper.read_threats(page_num - 1)  # change to 1 indexed
    pages = MongoHelper.get_threats_pages()
    return render_template('index.html', threats=threats, pages=pages, page_num=page_num)


@app.route('/details/<string:ip>')
def details(ip):
    threat = MongoHelper.read_threat(ip)
    for cve in threat['CVEs']:
        if 'cvss' not in threat['CVEs'][cve] or 'summary' not in threat['CVEs'][cve]:
            cve_info = MongoHelper.read_cve_by_name(cve)
            threat['CVEs'][cve]['cvss'] = cve_info['cvss']
            threat['CVEs'][cve]['summary'] = cve_info['summary']
        if 'ports' in threat['CVEs'][cve] and len(threat['CVEs'][cve]['ports']) == 0:
            threat['CVEs'][cve].pop('ports')
        if 'apps' in threat['CVEs'][cve] and len(threat['CVEs'][cve]['apps']) == 0:
            threat['CVEs'][cve].pop('apps')
    return render_template('details.html', threat=threat)


if __name__ == '__main__':
    app.run()
