import dns.message
import dns.query
import dns.exception
import logging
import json
import time
import asyncio

# === Логування ===
logging.basicConfig(
    level=logging.INFO,
    format='%(message)s',
    handlers=[
        logging.FileHandler("dns_output.txt", mode='w', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

ROOT_SERVERS = [
    '198.41.0.4', '199.9.14.201', '192.33.4.12', '202.12.27.33',
    '192.5.5.241', '198.41.0.10', '8.8.8.8', '1.1.1.1',
]

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
    if response.answer:
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.NS:
                for item in rrset:
                    ns_list.append(str(item.target).rstrip('.'))
    elif response.authority:
        for rrset in response.authority:
            if rrset.rdtype == dns.rdatatype.NS:
                for item in rrset:
                    ns_list.append(str(item.target).rstrip('.'))
    return ns_list

def resolve_ns_ip(ns_name):
    try:
        query = dns.message.make_query(ns_name, dns.rdatatype.A)
        response = dns.query.udp(query, "8.8.8.8", timeout=5)
        for answer in response.answer:
            if answer.rdtype == dns.rdatatype.A:
                for item in answer:
                    return str(item.address)
    except Exception as e:
        logging.warning(f"⚠️ Помилка при резолюції IP для {ns_name}: {e}")
    return None

def query_authoritative_ns(domain):
    labels = domain.strip('.').split('.')
    if len(labels) < 2:
        logging.error("❌ Некоректний домен")
        return []

    # === 1. Root query ===
    tld = labels[-1]
    root_query = dns.message.make_query(tld + '.', dns.rdatatype.NS)

    for root_ip in ROOT_SERVERS:
        try:
            logging.info(f"\n📡 Root-запит до {root_ip} для .{tld}")
            root_resp = dns.query.udp(root_query, root_ip, timeout=5)
            tld_ns_names = get_ns_from_response(root_resp)
            if tld_ns_names:
                break
        except Exception as e:
            logging.warning(f"⚠️ Root {root_ip} не відповів: {e}")
    else:
        logging.error("❌ Не вдалося отримати NS для TLD")
        return []

    # === 2. TLD query ===
    for tld_ns in tld_ns_names:
        tld_ip = resolve_ns_ip(tld_ns)
        if not tld_ip:
            continue

        try:
            query = dns.message.make_query(domain, dns.rdatatype.NS)
            logging.info(f"🌍 TLD-запит до {tld_ns} ({tld_ip}) для {domain}")
            response = dns.query.udp(query, tld_ip, timeout=5)
            ns_list = get_ns_from_response(response)
            if ns_list:
                return ns_list
        except Exception as e:
            logging.warning(f"⚠️ Помилка при запиті до {tld_ns}: {e}")

    logging.error("❌ Не вдалося отримати NS для домену")
    return []

def resolve_all_ns_ips(ns_names):
    ip_list = []
    for ns in ns_names:
        ip = resolve_ns_ip(ns)
        if ip:
            ip_list.append((ns, ip))
    return ip_list

async def query_ns_ip(domain, ns, ip, record_types):
    ip_result = {}
    logging.info(f"\n🖥️ Запити до {ns} ({ip})")

    for rtype in record_types:
        logging.info(f"📥 {rtype}-запит для {domain}")
        try:
            query = dns.message.make_query(domain, dns.rdatatype.from_text(rtype))
            start = time.time()
            response = await asyncio.to_thread(dns.query.udp, query, ip, timeout=5)
            elapsed = time.time() - start

            if response.answer:
                records = []
                for answer in response.answer:
                    for item in answer.items:
                        records.append(item.to_text())
                ip_result[rtype] = records
                logging.info(f"✅ {rtype}-запис отримано за {elapsed:.3f} сек: {records}")
            else:
                logging.info(f"ℹ️ Немає {rtype}-записів (за {elapsed:.3f} сек)")
        except dns.exception.Timeout:
            logging.error(f"❌ Таймаут при {rtype}-запиті")
        except dns.exception.DNSException as e:
            logging.error(f"❌ DNS помилка: {e}")
    return ns, ip, ip_result

async def analyze_domain(domain):
    logging.info(f"\n🔍 Початок аналізу домену: {domain}")
    start_total = time.time()

    authoritative_ns = query_authoritative_ns(domain)
    if not authoritative_ns:
        logging.error(f"❌ Не вдалося отримати NS для {domain}")
        return {}

    ns_ip_pairs = resolve_all_ns_ips(authoritative_ns)
    if not ns_ip_pairs:
        logging.error(f"❌ Не вдалося отримати IP авторитетних NS")
        return {}

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

def save_to_json(data, filename='dns_output.json'):
    cleaned = convert_bytes(data)
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(cleaned, f, indent=2, ensure_ascii=False)

# === Головний запуск ===
if __name__ == '__main__':
    site = input("Введіть домен для аналізу: ")
    result = asyncio.run(analyze_domain(site))
    if result:
        save_to_json(result)
    else:
        logging.error("❌ Аналіз завершився з помилками.")

