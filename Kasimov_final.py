
import json
import os
import zipfile
import requests
import pandas as pd

password = 'netology'
zip_path = "protected_archive.zip"

def unzip_file(zip_path, password):
    if zip_path.endswith(".zip"):
        directory_to_extract_to = os.path.dirname(os.path.abspath(zip_path))
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(directory_to_extract_to, pwd=bytes(password, 'utf-8'))

unzip_file(zip_path, password)


# VirusTotalAnalyzer
api_key = "8855876211e9e685efb3f3362691ac517d358f47406b2bcf988ab88ef3c40ca5"
file_path = "invoice-42369643.html"
upload_file_url = "https://www.virustotal.com/api/v3/files"
headers = {"accept": "application/json", "x-apikey": api_key}

def upload_to_virustotal(file_path, upload_file_url, headers):
    with open(file_path, "rb") as file:
        files = {"file": (file_path, file)}
        response = requests.post(upload_file_url, headers=headers, files=files)
    return response.json()["data"]["id"]

def get_sha256_from_virustotal(analysis_url, headers):
    response = requests.get(analysis_url, headers=headers)
    return response.json()["meta"]["file_info"]["sha256"]

def analyze_virustotal(analysis_url, headers):
    response = requests.get(analysis_url, headers=headers)
    return response.json()

def get_behavior_data_from_virustotal(behaviours_url, headers):
    return requests.get(behaviours_url, headers=headers)

def get_tags_report_from_virustotal(behavior_data):
    tags = behavior_data.json()["data"]["tags"]
    return pd.DataFrame(tags, columns=["tags"])

def get_hosts_report_from_virustotal(behavior_data):
    dns_lookups = behavior_data.json()["data"]["dns_lookups"]
    hosts = []
    for lookup in dns_lookups:
        hostname = lookup["hostname"]
        hosts.append(hostname)
        resolved_ips = lookup.get("resolved_ips", [])
        for resolved_ip in resolved_ips:
            hosts.append(resolved_ip)
    hosts_df = pd.DataFrame(hosts, columns=["hostname"])

    return hosts_df





def get_malware_report_from_virustotal(report_data):
    """
    Create dataframe from JSON data
    :return: pandas dataframe
    """
    data_arr = []
    report = report_data["data"]["attributes"]["results"]
    if report:
        with open("save_recording.json", "w") as file:
            json.dump(report, file, indent=4)

    for soft, res in report.items():
        data_arr.append([
            bool(res["result"]),
            res["engine_name"],
            res["result"]
        ])

    return pd.DataFrame(data_arr, columns=["is_detected", "software", "malware"])

file_id = upload_to_virustotal(file_path, upload_file_url, headers)
analysis_url = "https://www.virustotal.com/api/v3/analyses/{}".format(file_id)
behaviours_url = "https://www.virustotal.com/api/v3/files/{}/behaviour_summary".format(get_sha256_from_virustotal(analysis_url, headers))
report_data = analyze_virustotal(analysis_url, headers)
report_df = pd.concat(
    [
        get_malware_report_from_virustotal(report_data),
        get_tags_report_from_virustotal(get_behavior_data_from_virustotal(behaviours_url, headers)),
        get_hosts_report_from_virustotal(get_behavior_data_from_virustotal(behaviours_url, headers))
    ],
    axis=0)

print(report_df)


url = 'https://vulners.com/api/v3/burp/softwareapi/'
api_key = "QY6X9YK1FO1R42RU3RJ7H050X8SJ4OLPMNBUVOXPKQWXYPTIQFYOIP7U9RTI1GY3"
headers = {"Content-type": "application/json"}

def create_vulners_report_json():
    file_path = "report_vulners.json"
    with open("name_soft_analysis.json", "r") as file:
        data = json.load(file)
    report_json = {"report": []}
    for software in data:
        software_data = {
            "software": software["Program"],
            "version": software["Version"],
            "type": "software",
            "maxVulnerabilities": 100,
            "apiKey": api_key
        }
        response_json = requests.post(url, headers=headers, json=software_data)
        response_dict = json.loads(response_json.text)
        response_dict["software"] = software["Program"]
        response_dict["version"] = software["Version"]
        report_json["report"].append(response_dict)
    with open(file_path, "w") as vulners_report:
        json.dump(report_json, vulners_report, indent=4)

        return file_path

def get_vulners_report_df(report_json):
    with open(report_json, "r") as vulners_report:
        data = json.load(vulners_report)

    cve = []

    for result in data["report"]:
        data = result["data"]
        if data.get("search"):
            values = data.get("search")
            for value in values:
                cve.append([
                    result["software"],
                    result["version"],
                    True,
                    value["_source"]["cvelist"],
                    value["_source"]["href"],
                    value["_source"]["description"]
                ])
        else:
            cve.append([
                result["software"],
                result["version"],
                False,
                None,
                None,
                None
            ])
    return pd.DataFrame(cve, columns=["software", "version", "is_detected", "cve_list", "href", "description"])

def export_vulners_report_to_csv(report_df):
    return report_df.to_csv("analysis_vulners.csv", index=False, sep=";", encoding="utf-8")

def print_vulners_report_to_stdout(report_df):
    print(report_df)

report_json = create_vulners_report_json()
report_df = get_vulners_report_df(report_json)
print_vulners_report_to_stdout(report_df)
export_vulners_report_to_csv(report_df)
