import sys
import json
import requests
import censys.certificates

API_URL = "https://censys.io/api/v1"
UID = "97c34127-c350-45a6-81a2-7290b0a0f68d"
SECRET = "aHSyRxEsdiaDYbeQzdOkssNBLFMVdNnm"

data = {
                "query": "keyword",
                "page": 1,
                "fields": ["ip", "protocols", "location.country"]
            }
res = requests.post(API_URL + "/search/ipv4", data=json.dumps(data), auth=(UID, SECRET))
if res.status_code != 200:
    print("error occurred: %s" % res.json()["error"])
    sys.exit(1)
# for name, series in res.json()["raw_series"].iteritems():
#     print(series["name"], "was last updated at", series["latest_result"]["timestamp"])

print(res.json())
