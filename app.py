from fastapi import FastAPI
from prometheus_client import Counter, Gauge, generate_latest, CONTENT_TYPE_LATEST
from main import main
import datetime
import asyncio
import time
from fastapi.responses import Response

app = FastAPI()

expired_certificates_counter = Counter('expired_certificates', 'Number of expired certs')

cert_info = Gauge('cert_info', 'Info about the certficate',
                          ['serial_number', 'subject', 'host', 'san', 
                           'expiration_date','expiration_epoch'])

async def fetch_certificate_data():
    cache = await main()
    # print(f"in app.py: cache after await main(): {cache}")
    for cert in cache:

        serial_number_str = str(cert['serial number'])
        subject_str = str(cert['subject'])
        host = cert['host']
        sans = cert['SANs']
        expiration_epoch = cert['expiration epoch']

        expiration_date_str = cert.get('expiration date')
        if expiration_date_str:
            try:
                expiration_date = datetime.datetime.fromisoformat(expiration_date_str)
                # Compare the expiration date with the current date
                if datetime.datetime.now() > expiration_date:
                    print('found an expired cert')
                    expired_certificates_counter.inc()
            except ValueError:
                print(f"Invalid date format for certificate {serial_number_str}: {expiration_date_str}")

        
        cert_info.labels(
            serial_number=serial_number_str,
            subject=subject_str,
            host=host,
            san=sans,
            expiration_date=expiration_date_str,
            expiration_epoch=str(expiration_epoch)
        ).set(expiration_epoch)

        
@app.get("/metrics")
async def metrics():
    print('inside /metrics')
    await fetch_certificate_data()
    print('just finished fetch_certificate_data()')
    return generate_latest(), {'Content-Type': CONTENT_TYPE_LATEST}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)