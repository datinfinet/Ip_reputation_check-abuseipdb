##author vamshi.komakula

import requests

API_KEY_ABUSEIPDB = 'API'
API_KEY_IPSTACK = 'YOUR_IPSTACK_API_KEY'

IP_LIST = ['1.1.1.1', '2.2.2.2', '3.3.3.3']


def ip_check(ip):
    url_abuseipdb = f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip}'
    headers_abuseipdb = {
        'Accept': 'application/json',
        'Key': API_KEY_ABUSEIPDB,
    }
    
    response_abuseipdb = requests.get(url_abuseipdb, headers=headers_abuseipdb)
    data_abuseipdb = response_abuseipdb.json()
    
    if data_abuseipdb.get("data"):
        is_malicious = data_abuseipdb["data"]["isWhitelisted"] is False
        abuse_confidence_score = data_abuseipdb["data"]["abuseConfidenceScore"]
        status = "Malicious" if is_malicious else "Not malicious"
    else:
        status = "Unknown"
        abuse_confidence_score = None

    url_ipstack = f'http://api.ipstack.com/{ip}?access_key={API_KEY_IPSTACK}&fields=country_name,city'
    response_ipstack = requests.get(url_ipstack)
    data_ipstack = response_ipstack.json()

    print("IPStack Response:", data_ipstack)  # Added for debugging

    country = data_ipstack.get("country_name", "Unknown")
    city = data_ipstack.get("city", "Unknown")

    return {
        "status": status,
        "abuse_confidence_score": abuse_confidence_score,
        "country": country,
        "city": city
    }

if __name__ == "__main__":
    for ip_address in IP_LIST:
        ip_data = ip_check(ip_address)
        print(f"IP: {ip_address} - Status: {ip_data['status']} - Score: {ip_data['abuse_confidence_score']} - Country: {ip_data['country']} - City: {ip_data['city']}")
