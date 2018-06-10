import smtplib
from email.mime.text import MIMEText
import json

PORT = 25


class Notifier:

    def __init__(self):
        with open('../config.json') as f:
            config = json.loads(f.read())
        self.__emails = config['notification']['emails']

    def notify(self, total, specials):
        content = '本次威胁情报聚合完成，您有' + str(total) + '台主机可能受到威胁，'
        if len(specials) > 0:
            content += '其中您关注的'
        for cve in specials:
            content += cve['name'] + '有' + str(cve['count']) + '台主机可能受到威胁，'
        content += '可以前往202.112.51.123:5000查看。'
        print(content)
        for recipient in self.__emails:
            msg = MIMEText(content)
            msg['Subject'] = '分析完成！'
            msg['From'] = 'admin@threats-aggregation.com'
            msg['To'] = recipient
            s = smtplib.SMTP(recipient.split('@')[1], PORT)
            s.send_message(msg)
            s.quit()


if __name__ == '__main__':
    notifier = Notifier()
    notifier.notify(45, [{'name': 'CVE-2018-0171', 'count': 1}])
