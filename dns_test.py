import dns.resolver
import time
import socket

def get_ip_from_ns(nameserver):
    try:
        return socket.gethostbyname(nameserver)
    except socket.gaierror as e:
        print(f"❌ Не вдалося отримати IP для {nameserver}: {e}")
        return None

def query_root_server_for_tld(domain, start_time):
    tld = domain.split('.')[-1]
    print(f"\n🔎 Отримання NS-серверів для TLD: .{tld}")

    try:
        resolver = dns.resolver.Resolver()
        response = resolver.resolve(domain, 'NS')
        print(f"✅ Відповідь отримано за {round(time.time() - start_time, 3)} сек")
        print("📌 NS-сервери домену:")
        for ns in response:
            print(f" - {ns.target}")
    except Exception as e:
        print(f"❌ Помилка при запиті до root-сервера: {e}")


def get_authoritative_ns(domain):
    try:
        answers = dns.resolver.resolve(domain, 'NS')
        ns_list = [str(rdata.target).rstrip('.') for rdata in answers]
        return ns_list
    except Exception as e:
        print(f"❌ Помилка отримання NS записів: {e}")
        return []

def resolve_authoritative_ns_to_ip(authoritative_ns, start_time):
    ns_ips = []
    for ns in authoritative_ns:
        print(f"\n🌐 Отримання IP для {ns}")
        ip = get_ip_from_ns(ns)
        if ip:
            print(f"✅ IP: {ip}")
            ns_ips.append(ip)
    return ns_ips

def query_dns_records_from_ns(domain, ns_ip, start_time):
    resolver = dns.resolver.Resolver()
    record_types = ['A', 'MX', 'AAAA', 'TXT']
    
    for rtype in record_types:
        print(f"\n📥 Запит {rtype}-записів у {ns_ip} для {domain}")
        try:
            response = resolver.resolve(domain, rtype)
            print(f"✅ Відповідь за {round(time.time() - start_time, 3)} сек")
            for r in response:
                if rtype == 'TXT':
                    print(f"📄 TXT: {', '.join([str(s) for s in r.strings])}")
                elif rtype in ['A', 'AAAA']:
                    print(f"📄 {rtype}: {r.address}")
                elif rtype == 'MX':
                    print(f"📄 MX: {r.exchange}, пріоритет: {r.preference}")
        except Exception as e:
            print(f"❌ Помилка для {rtype}: {e}")

def analyze_domain(domain):
    start_time = time.time()
    print(f"\n🔍 Аналіз домену: {domain}")

    query_root_server_for_tld(domain, start_time)

    authoritative_ns = get_authoritative_ns(domain)
    if not authoritative_ns:
        print("❌ Не вдалося отримати авторитетні NS.")
        return
    ns_ips = resolve_authoritative_ns_to_ip(authoritative_ns, start_time)

    for ip in ns_ips:
        query_dns_records_from_ns(domain, ip, start_time)

    print(f"\n⏱️ Загальний час: {round(time.time() - start_time, 3)} сек")

# Приклад використання
site = input("Введіть сайт: ")
analyze_domain(site)


