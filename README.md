# Threats Aggregation and Reporting System

TODO: Brief intro here

### Supporting formats and Examples
- keywords: `tsinghua.edu.cn`
- Hosts: `23.0.0.0/8` or `59.66.131.241`
- IP: `166.111.55.176`

TODO: This should be extend to support more types and more formats

## Requirements

- Python 3.6.0
- Flask 0.12.2
- Censys 0.0.8
- Shodan 1.7.1
- MongoDB 3.6.4
- pymongo 3.6.1
- BeautifulSoup 4.6.0

## Installation

1. Install requirements

2. Enter working directory

   ```bash
   cd threats-aggregation
   ```

3. Start Database

   ```bash
   mongod --dbpath database/ --port 27017
   ```

4. Run aggregator

   ```bash
   python3 src/constroller
   ```

5. Start server

   ```bash
   export FLASK_APP=run.py
   flask run
   ```

## User Interface

TODO: User's Manual here