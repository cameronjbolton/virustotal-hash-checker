import csv
import os
import requests

def get_virustotal_api_key():
    if 'VT_API_KEY' not in os.environ:
        raise Exception("VT_API_KEY environment variable not set. Check system environment variables and try again.")
    return os.getenv('VT_API_KEY')
virustotal_api_key = get_virustotal_api_key()

# Load hashes from CSV file
hashes = []
with open('hashes.csv', newline='') as csvfile:
    hashReader = csv.reader(csvfile, delimiter=' ', quotechar='|')
    for row in hashReader:
        print("Loaded hash: " + row[0])
        hashes.append(row[0])

# Query VirusTotal for each hash
# https://docs.virustotal.com/reference/file-info
for hash in hashes:
    url = "https://www.virustotal.com/api/v3/files/{hash}"
    headers = {
    "accept": "application/json",
    "x-apikey": virustotal_api_key
    }
    response = requests.get(url.format(hash=hash), headers=headers)
    print(response.text)

