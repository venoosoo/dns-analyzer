import dns.message
import struct
import dns.query
import socket
import dns.exception
import dns.rdatatype
import dns.rcode
import logging
import json
import threading
import time
import asyncio
import random
import re
import sys

# === Логування ===
logging.basicConfig(
    level=logging.INFO,
    format='%(message)s',
    handlers=[
        logging.FileHandler("dns_output.txt", mode='w', encoding='utf-8'),
        logging.FileHandler("dns_output_all.txt", mode='a', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

ROOT_SERVERS = [
    '198.41.0.4', '199.9.14.201', '192.33.4.12', '192.5.5.241',
    '192.112.36.4', '198.97.190.53', '192.36.148.17', '193.0.14.129',
    '199.7.83.42', '202.12.27.33', '198.41.0.10', '199.7.91.13',
]

logging.basicConfig(level=logging.INFO, format='%(message)s')


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(3)


def build_query(txid, DOMAIN):
    q = struct.pack('>H', txid) + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    for part in DOMAIN.split('.'):
        q += bytes([len(part)]) + part.encode()
    q += b'\x00\x00\x01\x00\x01'
    return q

def build_fake_response(txid, DOMAIN):
    r = struct.pack('>H', txid) + b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'
    for part in DOMAIN.split('.'):
        r += bytes([len(part)]) + part.encode()
    r += b'\x00\x00\x01\x00\x01'
    r += b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04' + socket.inet_aton('1.2.3.4')
    return r

def send_real_query(DOMAIN, DNS_SERVER, DNS_PORT):
    txid = random.randint(0, 65535)
    query = build_query(txid, DOMAIN)
    sock.sendto(query, (DNS_SERVER, DNS_PORT))
    logging.info(f"[Real] Sent DNS query with TXID={txid}")
    try:
        data, _ = sock.recvfrom(512)
        recv_txid = struct.unpack('>H', data[0:2])[0]
        logging.info(f"[Real] Received response with TXID={recv_txid}")
        if recv_txid == txid:
            logging.info("[Real] Response TXID matches query TXID — атака не спрацювала")
        else:
            logging.info("[Real] Response TXID НЕ співпадає — потенційна вразливість")
    except socket.timeout:
        logging.info("[Real] Timeout waiting for DNS response")

def send_fake_responses(DOMAIN, DNS_SERVER, DNS_PORT):
    fake_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for _ in range(3000):
        fake_txid = random.randint(0, 65535)
        response = build_fake_response(fake_txid, DOMAIN)
        fake_sock.sendto(response, (DNS_SERVER, DNS_PORT))
    logging.info("[Fake] Sent 3000 fake DNS responses with random TXID")


def test_dns_amplification(server, port, domain):
    query = dns.message.make_query(domain, dns.rdatatype.ANY)
    try:
        response = dns.query.udp(query, server, timeout=3)
        rcode = response.rcode()
        size = len(response.to_wire())
        
        logging.info(f"Отримано відповідь від {server} з кодом {dns.rcode.to_text(rcode)} та розміром {size} байт")
        
        if rcode != dns.rcode.NOERROR:
            logging.info("Сервер повернув помилку або не обробив запит — захист працює")
        else:
            if size > 512:
                logging.warning("Велика відповідь (понад 512 байт) — потенційна вразливість до amplification атаки")
            else:
                logging.info("Відповідь має нормальний розмір — захист працює")
    except Exception as e:
        logging.error(f"Помилка при запиті: {e}")

def convert_bytes(obj):
    if isinstance(obj, bytes):
        return obj.decode('utf-8', errors='replace')
    elif isinstance(obj, dict):
        return {convert_bytes(k): convert_bytes(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_bytes(i) for i in obj]
    elif isinstance(obj, tuple):
        return tuple(convert_bytes(i) for i in obj)
    else:
        return obj

def get_ns_from_response(response):
    ns_list = []
    for rrset in response.answer + response.authority:
        if rrset.rdtype == dns.rdatatype.NS:
            for item in rrset:
                ns_list.append(str(item.target).rstrip('.'))
    return ns_list

def get_glue_ips(response, ns_name):
    ips = []
    for rrset in response.additional:
        if rrset.name.to_text().rstrip('.') == ns_name and rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
            for item in rrset:
                ips.append(item.address)
    return ips

def resolve_ns_ip(ns_name):
    ips = []
    try:
        query = dns.message.make_query(ns_name, dns.rdatatype.A)
        response = dns.query.udp(query, "8.8.8.8", timeout=5)
        if response.rcode() == dns.rcode.NOERROR:
            for answer in response.answer:
                if answer.rdtype == dns.rdatatype.A:
                    for item in answer:
                        ips.append(item.address)
    except Exception as e:
        logging.warning(f"⚠️ A-запит до {ns_name} не вдався: {e}")
        raise Exception(f"A-запит до {ns_name} не вдався")

    try:
        query = dns.message.make_query(ns_name, dns.rdatatype.AAAA)
        response = dns.query.udp(query, "8.8.8.8", timeout=5)
        if response.rcode() == dns.rcode.NOERROR:
            for answer in response.answer:
                if answer.rdtype == dns.rdatatype.AAAA:
                    for item in answer:
                        ips.append(item.address)
    except Exception as e:
        logging.warning(f"⚠️ AAAA-запит до {ns_name} не вдався: {e}")
        raise Exception(f"AAAA-запит до {ns_name} не вдався")

    return ips

def query_authoritative_ns(domain):
    labels = domain.strip('.').split('.')
    if len(labels) < 2:
        logging.error("❌ Некоректний домен")
        raise ValueError("Некоректний домен")

    tld = labels[-1]
    root_query = dns.message.make_query(tld + '.', dns.rdatatype.NS)

    tld_ns_names = []
    glue_ips = {}

    for root_ip in ROOT_SERVERS:
        try:
            logging.info(f"\n📡 Root-запит до {root_ip} для .{tld}")
            root_resp = dns.query.udp(root_query, root_ip, timeout=5)
            if root_resp.rcode() == dns.rcode.NXDOMAIN:
                logging.error("❌ Домен не існує (NXDOMAIN)")
                raise ValueError(f"Домен {domain} не існує (NXDOMAIN)")
            tld_ns_names = get_ns_from_response(root_resp)
            for ns in tld_ns_names:
                glue_ips[ns] = get_glue_ips(root_resp, ns)
            if tld_ns_names:
                break
        except Exception as e:
            logging.warning(f"⚠️ Root {root_ip} не відповів: {e}")
            raise

    for tld_ns in tld_ns_names:
        for tld_ip in glue_ips.get(tld_ns, resolve_ns_ip(tld_ns)):
            try:
                query = dns.message.make_query(domain, dns.rdatatype.NS)
                logging.info(f"🌍 TLD-запит до {tld_ns} ({tld_ip}) для {domain}")
                response = dns.query.udp(query, tld_ip, timeout=5)
                if response.rcode() == dns.rcode.NXDOMAIN:
                    logging.error("❌ Домен не існує (NXDOMAIN)")
                    raise ValueError(f"Домен {domain} не існує (NXDOMAIN)")
                ns_list = get_ns_from_response(response)
                if ns_list:
                    return ns_list
            except Exception as e:
                logging.warning(f"⚠️ Помилка при запиті до {tld_ns}: {e}")
                raise

    logging.error("❌ Не вдалося отримати NS для домену")
    raise ValueError("Не вдалося отримати NS для домену")


def resolve_all_ns_ips(ns_names):
    ip_list = []
    for ns in ns_names:
        ips = resolve_ns_ip(ns)
        for ip in ips:
            ip_list.append((ns, ip))
    return set(ip_list)

async def query_ns_ip(domain, ns, ip, record_types):
    ip_result = {}
    logging.info(f"\n🖥️ Запити до {ns} ({ip})")

    for rtype in record_types:
        logging.info(f"📥 {rtype}-запит для {domain}")
        try:
            query = dns.message.make_query(domain, dns.rdatatype.from_text(rtype))
            start = time.time()

            try:
                response = await asyncio.to_thread(dns.query.udp, query, ip, timeout=5)
            except OSError as e:
                logging.error(f"❌ Не вдалося підключитися до {ip} ({rtype}-запит): {e}")
                raise

            elapsed = time.time() - start

            if response.rcode() == dns.rcode.NXDOMAIN:
                logging.error(f"❌ Домен не існує (NXDOMAIN)")
                raise ValueError(f"Домен {domain} не існує (NXDOMAIN)")

            if response.answer:
                records = []
                for answer in response.answer:
                    for item in answer.items:
                        records.append(item.to_text())
                ip_result[rtype] = records
                logging.info(f"✅ {rtype}-запис отримано за {elapsed:.3f} сек: {records}")
            else:
                logging.info(f"ℹ️ Немає {rtype}-записів (за {elapsed:.3f} сек)")
        except Exception as e:
            logging.error(f"❌ Помилка при запиті до {ip} для {rtype}: {e}")
    return ns, ip, ip_result

async def analyze_domain(domain):
    RETRY_ATT = 3
    logging.info(f"\n🔍 Початок аналізу домену: {domain}")
    start_total = time.time()
    
    att = 0
    e = None
    while True:
        try:
            authoritative_ns = query_authoritative_ns(domain)
            if not authoritative_ns:
                logging.error(f"❌ Не вдалося отримати NS для {domain}")
                logging.error(f"⚠️ Повтор запиту")
                att += 1
            else:
                break 
        except Exception as err:
            logging.error(f"❌ Помилка при запиті до NS: {err}")
            e = err 
            att += 1

        if att == RETRY_ATT:
            logging.error(f"❌ Не вдалося отримати NS для {domain} після {RETRY_ATT} спроб")
            logging.error(f"⚠️ ПЕРЕВІРЬТЕ ПРАВИЛЬНІСТЬ ДОМЕНУ")
            if e:
                raise e
            else:
                raise Exception(f"Не вдалося отримати NS для {domain} після {RETRY_ATT} спроб")



        att = 0
    while True: 
        try:
            ns_ip_pairs = resolve_all_ns_ips(authoritative_ns)
            if not ns_ip_pairs:
                logging.error(f"❌ Не вдалося отримати IP авторитетних NS")
                logging.error(f"⚠️ Повтор запиту ")
                att += 1
            else:
                break
        except Exception as e:
            logging.error(f"❌ Помилка при отриманні IP авторитетних NS: {e}")

        if att == RETRY_ATT:
            logging.error(f"❌ Не вдалося отримати IP авторитетних NS після {RETRY_ATT} спроб")
            if e:
                raise e 
            else:
                raise Execption(f"❌ Не вдалося отримати IP авторитетних NS після {RETRY_ATT} спроб")

    record_types = ['A', 'AAAA', 'MX', 'TXT', 'SOA', 'CAA']
    tasks = [
        query_ns_ip(domain, ns, ip, record_types)
        for ns, ip in ns_ip_pairs
    ]
    results_raw = await asyncio.gather(*tasks)

    results = {}
    for ns, ip, ip_result in results_raw:
        if ns not in results:
            results[ns] = {}
        results[ns][ip] = ip_result

    total_elapsed = time.time() - start_total
    logging.info(f"\n🕒 Загальний час аналізу: {total_elapsed:.3f} сек")
    return results

def save_to_json_w(data, filename='dns_output.json'):
    cleaned = convert_bytes(data)
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(cleaned, f, indent=2, ensure_ascii=False)


def save_to_json_a(data, filename='dns_output_all.json'):
    cleaned = convert_bytes(data)
    with open(filename, 'a', encoding='utf-8') as f:
        json.dump(cleaned, f, indent=2, ensure_ascii=False)


def is_valid_domain(domain):
    domain_regex = re.compile(
        r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)'     # Перша частина
        r'(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*' # Субдомени
        r'\.[A-Za-z]{2,}$'                   # TLD
    )
    return bool(domain_regex.fullmatch(domain))



def dns_security_check(domain):
    DNS_SERVER = domain
    DNS_PORT = 53
    DOMAIN = 'example.com'
    logging.info(f"Перевірка сервера {domain} на DNS CACHE POISONING")
    t_fake = threading.Thread(target=send_fake_responses(DOMAIN, DNS_SERVER, DNS_PORT))
    t_real = threading.Thread(target=send_real_query(DOMAIN,DNS_SERVER, DNS_PORT))

    t_fake.start()
    time.sleep(0.5)  
    t_real.start()

    t_fake.join()
    t_real.join()
    logging.info(f"Перевірка сервера {domain} на DNS AMPLIFICATION ATTACK")
    test_dns_amplification(DNS_SERVER, DNS_PORT, DOMAIN)


if __name__ == '__main__':
    if len(sys.argv) == 2:
        site = sys.argv[1]
    else:
        site = input("Введіть домен для аналізу: ")
        dns_security_check("199.9.14.201")

    if not is_valid_domain(site):
        logging.info("❌ Неправильний формат домену")
        sys.exit(1)  

   
    result = asyncio.run(analyze_domain(site))
    if result:
        save_to_json_w(result)
        save_to_json_a(result)
    else:
        logging.error("❌ Аналіз завершився з помилками.")
        sys.exit(1)
