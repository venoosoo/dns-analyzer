import dns.resolver
import dns.exception
import time
import logging
import json
import concurrent.futures

# ==== Логування у файл та консоль ====
logging.basicConfig(
    level=logging.INFO,
    format='%(message)s',
    handlers=[
        logging.FileHandler("dns_output.txt", mode='a', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

ROOT_SERVERS = [
    '198.41.0.4',    # a.root-servers.net
    '199.9.14.201',  # b.root-servers.net
    '192.33.4.12',   # c.root-servers.net
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

def query_tld_ns(domain):
    tld = domain.split('.')[-1]
    logging.info(f"\n🔎 Отримання NS-серверів для TLD: .{tld}")
    start = time.time()
    try:
        answers = dns.resolver.resolve(domain, 'NS')
        elapsed = round(time.time() - start, 3)
        ns_list = [str(r.target).rstrip('.') for r in answers]
        logging.info(f"✅ Знайдено {len(ns_list)} NS за {elapsed} сек:")
        for ns in ns_list:
            logging.info(f" - {ns}")
        return ns_list
    except dns.resolver.NXDOMAIN:
        logging.error(f"❌ Домен {domain} не існує (NXDOMAIN)")
    except dns.exception.DNSException as e:
        logging.error(f"❌ Помилка DNS: {e}")
    return []

def resolve_ns_ips(ns_list):
    ns_ips = {}
    for ns in ns_list:
        ips = []
        for rtype in ('A', 'AAAA'):
            try:
                answers = dns.resolver.resolve(ns, rtype, raise_on_no_answer=False)
                if answers.rrset:
                    for r in answers:
                        ips.append(r.address)
            except dns.exception.DNSException as e:
                logging.warning(f"⚠️ {rtype}-запит до {ns} дав помилку: {e}")
        if ips:
            ns_ips[ns] = ips
        else:
            logging.error(f"❌ Не вдалося отримати жодної IP для {ns}")
    return ns_ips

def query_records(domain, ns_ips):
    record_types = ['A', 'AAAA', 'MX', 'TXT', 'SOA', 'CAA']
    results = {}

    def query_ns_ip(ns, ip):
        ip_result = {}
        logging.info(f"\n🖥️ Запити до {ns} ({ip})")
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [ip]
        for rtype in record_types:
            logging.info(f"📥 {rtype}-запис для {domain}")
            start = time.time()
            try:
                response = resolver.resolve(domain, rtype, raise_on_no_answer=False)
                elapsed = round(time.time() - start, 3)
                if response.rrset:
                    logging.info(f"✅ {rtype} отримано за {elapsed} сек")
                    records = []
                    for r in response:
                        if rtype == 'TXT':
                            records.append([s.decode('utf-8', errors='replace') for s in r.strings])
                            logging.info(f"📄 TXT: {', '.join(records[-1])}")
                        elif rtype in ('A', 'AAAA'):
                            records.append(r.address)
                            logging.info(f"📄 {rtype}: {r.address}")
                        elif rtype == 'MX':
                            records.append({'exchange': str(r.exchange), 'priority': r.preference})
                            logging.info(f"📄 MX: {r.exchange}, пріоритет: {r.preference}")
                        elif rtype == 'SOA':
                            records.append({
                                'mname': str(r.mname),
                                'rname': str(r.rname),
                                'serial': r.serial
                            })
                            logging.info(f"📄 SOA: {r.mname} {r.rname} (ser: {r.serial})")
                        elif rtype == 'CAA':
                            records.append({
                                'flags': r.flags,
                                'tag': r.tag,
                                'value': r.value.decode() if isinstance(r.value, bytes) else r.value
                            })
                            logging.info(f"📄 CAA: {r.flags} {r.tag} {r.value}")
                    ip_result[rtype] = records
                else:
                    logging.info(f"ℹ️ Записів типу {rtype} немає")
            except dns.resolver.NoAnswer:
                logging.info(f"ℹ️ Немає відповіді для {rtype}")
            except dns.resolver.NXDOMAIN:
                logging.error(f"❌ NXDOMAIN при запиті {rtype}")
            except dns.exception.Timeout:
                logging.error(f"❌ Таймаут при запиті {rtype}")
            except Exception as e:
                logging.error(f"❌ Помилка при {rtype}: {e}")
        return ns, ip, ip_result

    futures = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        for ns, ips in ns_ips.items():
            for ip in ips:
                futures.append(executor.submit(query_ns_ip, ns, ip))

        for future in concurrent.futures.as_completed(futures):
            ns, ip, ip_result = future.result()
            if ns not in results:
                results[ns] = {}
            results[ns][ip] = ip_result



def analyze_domain(domain):
    start_time = time.time()
    logging.info(f"🔍 Початок аналізу домену: {domain}")

    authoritative_ns = query_tld_ns(domain)
    if not authoritative_ns:
        return {}

    ns_ips = resolve_ns_ips(authoritative_ns)
    if not ns_ips:
        return {}

    records = query_records(domain, ns_ips)

    total_time = round(time.time() - start_time, 3)
    logging.info(f"⏱️ Загальний час: {total_time} сек")

    return {
        'domain': domain,
        'ns': authoritative_ns,
        'ns_ips': ns_ips,
        'records': records,
        'elapsed': total_time
    }

def save_to_json(data, filename='dns_output.json'):
    cleaned = convert_bytes(data)
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(cleaned, f, indent=2, ensure_ascii=False)

# ==== Головний запуск ====
if __name__ == '__main__':
    site = input("Введіть домен для аналізу: ")
    result = analyze_domain(site)
    if result:
        save_to_json(result)

