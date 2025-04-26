import dns.resolver
import dns.exception
import time
import logging

# ===== Налаштування логування =====
logging.basicConfig(
    level=logging.INFO,
    format='%(message)s',
    handlers=[
        # Для накопичення логів змінити на mode='a'
        logging.FileHandler("dns_output.txt", mode='a', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

# ===== Список кореневих серверів (root hints) =====
ROOT_SERVERS = [
    '198.41.0.4',    # a.root-servers.net
    '199.9.14.201',  # b.root-servers.net
    '192.33.4.12',   # c.root-servers.net
    # ... можна додати залишок за потреби
]


def query_tld_ns(domain):
    """Отримати авторитетні NS для домену через локальний резолвер"""
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
    """Отримати IPv4 та IPv6 адреси для кожного NS"""
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
    """Запитувати різні DNS-записи у кожного NS"""
    record_types = ['A', 'AAAA', 'MX', 'TXT', 'SOA', 'CAA']

    for ns, ips in ns_ips.items():
        for ip in ips:
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
                        for r in response:
                            if rtype == 'TXT':
                                texts = [s.decode() for s in r.strings]
                                logging.info(f"📄 TXT: {', '.join(texts)}")
                            elif rtype in ('A', 'AAAA'):
                                logging.info(f"📄 {rtype}: {r.address}")
                            elif rtype == 'MX':
                                logging.info(f"📄 MX: {r.exchange}, пріоритет: {r.preference}")
                            elif rtype == 'SOA':
                                logging.info(f"📄 SOA: {r.mname} {r.rname} (ser: {r.serial})")
                            elif rtype == 'CAA':
                                logging.info(f"📄 CAA: {r.flags} {r.tag} {r.value}")
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


def analyze_domain(domain):
    start_time = time.time()
    logging.info(f"🔍 Початок аналізу домену: {domain}")

    # 1. Отримуємо NS-записи
    authoritative_ns = query_tld_ns(domain)
    if not authoritative_ns:
        return

    # 2. Отримуємо IP NS
    ns_ips = resolve_ns_ips(authoritative_ns)
    if not ns_ips:
        return

    # 3. Запитуємо DNS-записи без додаткової фільтрації TCP
    query_records(domain, ns_ips)

    logging.info(f"⏱️ Загальний час: {round(time.time() - start_time, 3)} сек")


if __name__ == '__main__':
    site = input("Введіть домен для аналізу: ")
    analyze_domain(site)
