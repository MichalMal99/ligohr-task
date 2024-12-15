import json
import requests
from fastapi import FastAPI, Request, HTTPException
from typing import List

app = FastAPI()

# Przechowywanie listy dozwolonych prefiksów IP
allowed_ips: List[str] = []

# Adres URL do pobierania zakresów IP AWS
AWS_IP_RANGES_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"


def fetch_aws_ip_ranges() -> List[str]:
    """
    Pobiera zakresy IP z pliku JSON udostępnianego przez AWS i filtruje dane dla regionu eu-west-1.
    """
    try:
        response = requests.get(AWS_IP_RANGES_URL)
        response.raise_for_status()
        data = response.json()

        # Wyodrębnianie prefiksów dla regionu eu-west-1 i usługi EC2
        return [
            prefix['ip_prefix']
            for prefix in data.get('prefixes', [])
            if prefix['region'] == 'eu-west-1' and prefix['service'] == 'EC2'
        ]
    except (requests.RequestException, KeyError, json.JSONDecodeError) as e:
        print(f"Błąd podczas pobierania danych IP: {e}")
        return []


def is_ip_allowed(client_ip: str, allowed_ranges: List[str]) -> bool:
    """
    Sprawdza, czy podany adres IP znajduje się w liście dozwolonych zakresów.
    """
    from ipaddress import ip_address, ip_network

    try:
        client_ip_obj = ip_address(client_ip)
        for ip_range in allowed_ranges:
            if client_ip_obj in ip_network(ip_range):
                return True
    except ValueError as e:
        print(f"Nieprawidłowy adres IP: {client_ip} ({e})")

    return False


@app.on_event("startup")
def initialize_allowed_ips():
    """
    Funkcja uruchamiana przy starcie serwera - odświeża listę dozwolonych adresów IP.
    """
    global allowed_ips
    allowed_ips = fetch_aws_ip_ranges()
    print(f"Załadowano {len(allowed_ips)} zakresów IP.")


@app.post("/verify")
async def verify_request(request: Request):
    """
    Weryfikuje, czy klient ma dozwolony dostęp na podstawie jego adresu IP.
    """
    client_ip = request.client.host  # Pobieranie IP klienta

    if is_ip_allowed(client_ip, allowed_ips):
        return {"status": "200 OK", "message": "Access granted"}

    raise HTTPException(status_code=401, detail="Unauthorized")


@app.get("/refresh")
def refresh_ip_ranges():
    """
    Ręcznie odświeża listę dozwolonych adresów IP.
    """
    global allowed_ips
    allowed_ips = fetch_aws_ip_ranges()
    return {"status": "IPs refreshed", "count": len(allowed_ips)}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)