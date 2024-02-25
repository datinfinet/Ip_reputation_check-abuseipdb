
import requests

API_KEY = 'ca4634f5ccfe89afac99a7553979552bbdec0617d0a05f33f2efd89b54c757771532a86d1989242f'
IP_LIST = ['52.189.252.193','149.40.52.227','104.28.156.213']


def check_ip_reputation(ip):
    url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip}'
    headers = {
        'Accept': 'application/json',
        'Key': API_KEY,
    }
    
    response = requests.get(url, headers=headers)
    data = response.json()
    
    return data

if __name__ == "__main__":
    for ip_address in IP_LIST:
        ip_data = check_ip_reputation(ip_address)
        if ip_data.get("data"):
            is_malicious = ip_data["data"]["isWhitelisted"] is False
            abuse_confidence_score = ip_data["data"]["abuseConfidenceScore"]
            status = "Malicious" if is_malicious else "Not malicious"
            print(f"IP: {ip_address} - Status: {status} - Score: {abuse_confidence_score}")
        else:
            print(f"No data found for the IP address: {ip_address}")
