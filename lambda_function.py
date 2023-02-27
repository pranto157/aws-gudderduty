import re
import csv
import logging
import json
import tempfile
from datetime import datetime
from os import environ
from io import BytesIO
from zipfile import ZipFile


import boto3
import requests
from botocore.vendored import requests as boto_req
from netaddr import IPSet, cidr_merge


URLS = [

]
ip_pattern = re.compile(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:\d+)?')
time_stamp = datetime.now().strftime("%Y%m%d-%H%M%S")


def formatted_ip(ip_text):
    match = ip_pattern.match(ip_text)
    if match:
        return match.group(1) + (match.group(2) or '')


def get_ips_from_csv(_file):
    ips = []
    tmp_csv = tempfile.NamedTemporaryFile()
    tmp_csv.write(_file.read())
    ifile  = open(tmp_csv.name, "r")
    fields = ['# "first_seen_utc"', 'ioc_id', 'ioc_value', 'ioc_type', 'threat_type', 'fk_malware', 'malware_alias', 
              'malware_printable', 'last_seen_utc', 'confidence_level', 'reference', 'tags', 'anonymous', 'reporter']
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
    batch_size = 250
    max_size = 35 * 1024 * 1024  # 35 MB
    temp_files = []
    batch = []
    batch_size_bytes = 0
    file_counter = 1

    for line in cidr_ips:
        line = str(line).rstrip()
        batch.append(line.rstrip())
        batch_size_bytes += len(line.encode('utf-8'))
        if len(batch) >= batch_size or batch_size_bytes >= max_size:
            temp_file = tempfile.NamedTemporaryFile(prefix=f"batch_{file_counter}_{time_stamp}_", delete=False)
            temp_files.append(temp_file)
            for line in batch:
                temp_file.write(line.encode('utf-8'))
                temp_file.write(b'\n')
            batch.clear()
            batch_size_bytes = 0
            file_counter += 1

    if len(batch) > 0:
        temp_file = tempfile.NamedTemporaryFile(prefix=f"batch_{file_counter}_{time_stamp}_", delete=False)
        temp_files.append(temp_file)
        for line in batch:
            temp_file.write(line.encode('utf-8'))
            temp_file.write(b'\n')
    return temp_files


def send_response(event, context, responseStatus, responseData, resourceId, reason=None):
    logging.getLogger().debug("send_response - Start")

    responseUrl = event['ResponseURL']
    logging.getLogger().debug(responseUrl)

    cw_logs_url = "https://console.aws.amazon.com/cloudwatch/home?region=%s#logEventViewer:group=%s;stream=%s"%(context.invoked_function_arn.split(':')[3], context.log_group_name, context.log_stream_name)
    logging.getLogger().debug("Logs: cw_logs_url")

    responseBody = {}
    responseBody['Status'] = responseStatus
    responseBody['Reason'] = reason or ('See the details in CloudWatch Logs: ' +  cw_logs_url)
    responseBody['PhysicalResourceId'] = resourceId
    responseBody['StackId'] = event['StackId']
    responseBody['RequestId'] = event['RequestId']
    responseBody['LogicalResourceId'] = event['LogicalResourceId']
    responseBody['NoEcho'] = False
    responseBody['Data'] = responseData

    json_responseBody = json.dumps(responseBody)

    logging.getLogger().debug("Response body:\n" + json_responseBody)

    headers = {
        'content-type' : '',
        'content-length' : str(len(json_responseBody))
    }

    try:
        response = boto_req.put(responseUrl,
                                data=json_responseBody,
                                headers=headers)
        logging.getLogger().debug("Status code: " + response.reason)

    except Exception as error:
        logging.getLogger().error("send(..) failed executing requests.put(..): " + str(error))

    logging.getLogger().debug("send_response - End")

def upload_to_S3(_files):
    s3 = boto3.client('s3')
    for _file in _files:
        _file_name = _file.name.replace('/tmp/', '')
        logging.getLogger().info(f"Uploading {_file_name} to S3")
        output_file_Name = f"mundurraga/input_files/{_file_name}.txt"
        s3.upload_file(_file.name, environ['S3_BUCKET'], output_file_Name, ExtraArgs={'ContentType': "application/CSV"})


def upload_to_guardduty(_files):
    guardduty = boto3.client('guardduty')
    response = guardduty.list_detectors()

    if len(response['DetectorIds']) == 0:
        raise Exception('Failed to read GuardDuty info. Please check if the service is activated')

    detector_id = response['DetectorIds'][0]
    
    counter = 0
    for temp_file in _files:
        try:
            _file_name = temp_file.name.replace('/tmp/', '')
            logging.getLogger().info(f"Uploading {_file_name} to Guardduty")
            response = guardduty.create_threat_intel_set(
                DetectorId=detector_id,
                Name=f'IPSet_{counter + 1}_{time_stamp}',
                Format='TXT',
                Location=f"s3://{environ['S3_BUCKET']}/mundurraga/input_files/{_file_name}.txt",
                Activate=True,
                Tags={
                    'filename': _file_name
                }
            )
            counter += 1
        except Exception as error:
            logging.getLogger().error(str(error))
            continue
    return counter


def lambda_handler(event, context):
    responseStatus = 'SUCCESS'
    reason = None
    responseData = {}
    result = {
        'statusCode': '200',
        'body':  {'message': 'success'}
    }

    try:
        global log_level
        log_level = str(environ['LOG_LEVEL'].upper())
        if log_level not in ['DEBUG', 'INFO','WARNING', 'ERROR','CRITICAL']:
            log_level = 'ERROR'
        logging.getLogger().setLevel(log_level)

        logging.getLogger().info(event)
        request_type = event['RequestType'].upper()  if ('RequestType' in event) else ""
        logging.getLogger().info(request_type)

        if 'DELETE' in request_type:
            if 'ResponseURL' in event:
                send_response(event, context, responseStatus, responseData, event['LogicalResourceId'], reason)

            return json.dumps(result)

        # Aggregate IP's from URLs
        ips = []
        for url in URLS:
            ips.extend(download_url(url))

        cidr_ips = aggregate_ip_cidr_block(ips)
        _files = create_batch_file(cidr_ips)

        # Upload to S3
        upload_to_S3(_files)
        # Guard Duty
        counter = upload_to_guardduty(_files)
        # Update result data
        result = {
            'statusCode': '200',
            'body':  {'message': f"Create {counter} guardduty out of {len(_files)}"}
        }

    except Exception as error:
        logging.getLogger().error(str(error))
        responseStatus = 'FAILED'
        reason = str(error)
        result = {
            'statusCode': '500',
            'body':  {'message': reason}
        }

    finally:
        if 'ResponseURL' in event:
            send_response(event, context, responseStatus, responseData, event['LogicalResourceId'], reason)

    return json.dumps(result)
