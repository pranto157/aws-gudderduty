import logging
import re
from io import BytesIO
from zipfile import ZipFile
import csv
import tempfile
from netaddr import IPSet, cidr_merge

import requests


URLS = [
    "https://lists.blocklist.de/lists/all.txt",
    # "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    # "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    # "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
    # "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
    # "https://threatfox.abuse.ch/export/csv/ip-port/full",
    # "http://reputation.alienvault.com/reputation.data",
    # "https://cinsscore.com/list/ci-badguys.txt",
    # "https://www.talosintelligence.com/documents/ip-blacklist",
    # "https://www.dan.me.uk/torlist/"

]
ip_pattern = re.compile(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:\d+)?')
fields = ['# "first_seen_utc"', 'ioc_id', 'ioc_value', 'ioc_type', 'threat_type', 'fk_malware', 'malware_alias', 'malware_printable', 'last_seen_utc', 'confidence_level', 'reference', 'tags', 'anonymous', 'reporter']



ip_file = tempfile.NamedTemporaryFile()

def formatted_ip(ip_text):
    match = ip_pattern.match(ip_text)
    if match:
        return match.group(1) + (match.group(2) or '')

def get_ips_from_csv(_file):
    ips = []
    tmp_csv = tempfile.NamedTemporaryFile()
    tmp_csv.write(_file.read())
    ifile  = open(tmp_csv.name, "r")
    csv_reader = csv.DictReader(ifile, fieldnames=fields, delimiter=',')
    for row in csv_reader:
        if 'ioc_value' in row and row["ioc_value"] is not None:
            input_str = row["ioc_value"].strip()
            if input_str.startswith('"') and input_str.endswith('"'):
                input_str = input_str[1:-1]
                format_ip = formatted_ip(input_str)
                if format_ip and format_ip not in ips:
                    ips.append(format_ip)
    return ips

def extract_zip(content):
    ips = []
    _unzip = ZipFile(BytesIO(content))
    files = _unzip.namelist()
    for _file in files:
        if _file.endswith(".csv"):
            csv_ips = get_ips_from_csv(_unzip.open(_file))
            ips.extend(csv_ips)
        else:
            for line in _unzip.open(_file).readlines():
                format_ip = formatted_ip(line.decode('utf-8'))
                if format_ip and format_ip not in ips:
                    ips.append(format_ip)
    return ips

def download_url(url):
    ips = []
    try:
        response = requests.get(url)
        if 'application/zip' in response.headers.get("Content-Type"):
            zip_ips = extract_zip(response.content)
            ips.extend(zip_ips)
        else:
            ip_list = response.text.split("\n")
            for ip in ip_list:
                format_ip = formatted_ip(ip)
                if format_ip and format_ip not in ips:
                    ips.append(format_ip)
    except requests.exceptions.ConnectionError as e:
        logging.error(e.message)
    return ips

def aggregate_ip_cidr_block(ips):
    cidr_ips = []
    ip_set = IPSet(ips)
    cidr_blocks = cidr_merge(ip_set)
    for cidr in cidr_blocks:
        cidr_ips.append(cidr)
    return cidr_ips

def create_batch_file(cidr_ips):
    batch_size = 250000
    max_size = 35 * 1024 * 1024  # 35 MB
    temp_files = []
    batch = []
    batch_size_bytes = 0
    file_counter = 1  # Counter for generating unique temporary file names

    for line in cidr_ips:
        line = str(line).rstrip()
        batch.append(line.rstrip())
        batch_size_bytes += len(line.encode('utf-8'))
        if len(batch) >= batch_size or batch_size_bytes >= max_size:
            temp_file = tempfile.NamedTemporaryFile(prefix=f"temp{file_counter}_", delete=False)
            temp_files.append(temp_file)
            for line in batch:
                temp_file.write(line.encode('utf-8'))
                temp_file.write(b'\n')
            batch.clear()
            batch_size_bytes = 0
            file_counter += 1

    if len(batch) > 0:
        temp_file = tempfile.NamedTemporaryFile(prefix=f"temp{file_counter}_", delete=False)
        temp_files.append(temp_file)
        for line in batch:
            temp_file.write(line.encode('utf-8'))
            temp_file.write(b'\n')
    
    return temp_files


if __name__ == "__main__":
    ips = []
    for url in URLS:
        ips.extend(download_url(url))

    cidr_ips = aggregate_ip_cidr_block(ips)
    _files = create_batch_file(cidr_ips)
    import ipdb; ipdb.set_trace()
    pass
