import asyncio
import aiohttp
import datetime
import subprocess
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import time
import os
import json

async def fetch_dns_records(session, zone_id):
    page, all_records = 1, []
    while True:
        dns_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?page={page}"
        async with session.get(dns_url) as response:
            if response.status == 200:
                dns_data = await response.json()
                records = [(record['name'], record['type'], record['content']) for record in dns_data['result']]
                all_records.extend(records)
                total_pages = dns_data['result_info']['total_pages']
                if page >= total_pages:
                    break
                page += 1
            else:
                print(f"Error fetching DNS records for zone id {zone_id}: {response.status}")
                return []
    return all_records

def parse_nmap_output(nmap_output):
    lines = nmap_output.split('\n')
    ports = []
    for line in lines:
        if 'Ports:' in line:
            parts = line.split('Ports: ')[1].split(',')
            for part in parts:
                port_info = part.strip().split('/')
                if 'open' in port_info:
                    port = int(port_info[0])
                    ports.append(port)
    return ports

async def fetch_ssl_certificate(ip, port, timeout=5):
    try:
        # Enforce the timeout for the entire operation
        return await asyncio.wait_for(_fetch_ssl_certificate_impl(ip, port), timeout)
    except asyncio.TimeoutError:
        print(f'Timeout while fetching SSL certificate for {ip}:{port}')
    except Exception as e:
        print(f'Error fetching SSL certificate for {ip}:{port} - {e}')
    return None


#function extracts and serialize certificate data
    # Extract the necessary information from the certificate
    # Convert it into a native Python datatype (e.g., dict, list, string, etc.)
def serialize_certificate(cert_obj):
    serialized_cert = {
        "subject": cert_obj.subject.rfc4514_string(),
        "issuer": cert_obj.issuer.rfc4514_string(),
        "serial_number": cert_obj.serial_number,
        "not_valid_before": cert_obj.not_valid_before.isoformat(),
        "not_valid_after": cert_obj.not_valid_after.isoformat(),
    }
    return serialized_cert

async def _fetch_ssl_certificate_impl(ip, port):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    writer = None
    try:
        # Establish connection without a specific timeout here
        reader, writer = await asyncio.open_connection(ip, port, ssl=context, server_hostname=ip)
        cert = writer.get_extra_info('ssl_object').getpeercert(True)
        # Decode the certificate using cryptography x509
        # print(f'Got certificate for {ip}:{port} - {cert[:6]}')
        cert_obj = x509.load_der_x509_certificate(cert, default_backend())
        print(f'Got certificate for {ip}:{port} - {cert[:6]} - {cert_obj}')
        serialize_cert = serialize_certificate(cert_obj)
        return serialize_cert
    finally:
        # Ensure the writer is closed properly
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception as e:
                print(f'Error closing connection for {ip}:{port} - {e}')

async def run_nmap_scan(ip, counter_list):
    cmd = f"nmap -sT {ip} --top-ports 1000 -oG -"
    process = await asyncio.create_subprocess_shell(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    stdout, stderr = await process.communicate()
    counter_list[0] += 1
    print(f"ip address counter list: {counter_list[0]}")
    # print(f"ip address {ip} scraped. counter list: {counter_list[0]}")
    if process.returncode != 0:
        return f"Error scanning {ip}: {stderr.decode()}"
    output = stdout.decode()
    ports = parse_nmap_output(output)
    if not ports:
        # print('ports variable is empty because no open ports found, returning None')
        await process.wait()
        return None

    # print(f"before fetching cert, here is the ip: {ip} and its ports: {ports}")
    ssl_tasks = [fetch_ssl_certificate(ip, port) for port in ports]    
    certificates = await asyncio.gather(*ssl_tasks)
    certificates = [cert for cert in certificates if cert is not None]
    await process.wait()
    return {
        "certificates" : certificates,
        "host_ip" : ip
    }

def get_ips_cache(cache_file):
    try:
        if os.path.exists(cache_file):
            with open(cache_file, 'r') as file:
                ips_cache = json.load(file)
        else:
            ips_cache = {}
    except json.decoder.JSONDecodeError:
        print(f"Warning: Cache file {cache_file} is empty or corrupt. Starting with an empty cache.")
        ips_cache = {}
    return ips_cache

def cache_result(ip, result, ips_cache, cache_file):
    ips_cache[ip] = {
        'timestamp' : time.time(),
        'result' : result
    }
    with open(cache_file, 'w') as file:
        json.dump(ips_cache, file)

async def main():
    main_start_time = time.time()
    token = "vExiIoZyyP18B7hf7sEXi8j5MdAu7HfRVqAAQI8V" #fake token—to put token in python env variable.
    headers = {
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json",
    }
    #fake zone_ids
    zone_ids = [
        "a211d8308d5bbb10abbc1aAAA93e25a4", # exampledev.com
        "f81cb69545c63fbccc25d5b8824150c1", # exampleinc.com
        "ad09ce17c0c221038b7ff1e3aafc6060", # fuaidir-it-jason.com
    ]
    cache_file = 'ip_scan_cache.json'
    #load existing cache
    ips_cache = get_ips_cache(cache_file)
    all_dns_records = []
    async with aiohttp.ClientSession(headers=headers) as session:
        start_time = time.time()

        for zone_id in zone_ids:

            dns_records = await fetch_dns_records(session, zone_id)
            all_dns_records.extend(dns_records)

        end_time = time.time()
        execution_time = end_time - start_time
        print(f"DNS records all zones fetched execution time: {execution_time:.4f} seconds")
    # dns records, verified via CloudFlare Dashboard
    ip_addresses = {record[2] for record in all_dns_records if record[1] in ('A', 'AAAA')} #mostly ipv4 but several ipv6 addresses 
    counter_list = [0]
    tasks = []
    for ip in ip_addresses:
        cached_ip = ips_cache.get(ip)
        if not (cached_ip and time.time() - ips_cache[ip]['timestamp'] < 604800):            
            tasks.append(run_nmap_scan(ip, counter_list))

    results = await asyncio.gather(*tasks)
    filtered_results = [
        result for result in results
        if result is not None and isinstance(result, dict) and 'certificates' in result
    ]

    cache = []
    for result in filtered_results:
        cache_result(result['host_ip'], result, ips_cache, cache_file)
        # Assuming 'cert' is a dictionary with serialized certificate data
        # Access the data directly from the dictionary
        for cert in result['certificates']:
            sans = cert.get('SANs', 'No SANs')
            expiration_date = cert.get('not_valid_after')
            if expiration_date:
                expiration_date_str = str(expiration_date)
                expiration_epoch = int((datetime.datetime.fromisoformat(expiration_date_str) - datetime.datetime(1970, 1, 1)).total_seconds())
            else:
                expiration_date_str = 'Unknown'
                expiration_epoch = 'Unknown'            
            cache_entry = {
                "serial number": cert.get('serial_number'), 
                "subject": cert.get('subject'), 
                "expiration date": expiration_date_str,
                "expiration epoch": expiration_epoch,
                "SANs": sans,
                "extensions": sans, 
                "host": result['host_ip']           
            }
            cache.append(cache_entry)

    main_end_time = time.time()
    main_execution_time = main_end_time - main_start_time
    print(f"main() execution time: {main_execution_time:.4f} seconds")
    return cache

asyncio.run(main())