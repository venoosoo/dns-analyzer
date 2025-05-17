import asyncio
import logging
from dns_test import analyze_domain


domains_50 = [
    "google.com", "facebook.com", "youtube.com", "amazon.com", "wikipedia.org",
    "twitter.com", "instagram.com", "linkedin.com", "netflix.com", "reddit.com",
    "bing.com", "yahoo.com", "apple.com", "microsoft.com", "stackoverflow.com",
    "github.com", "mozilla.org", "dropbox.com", "salesforce.com", "adobe.com",
    "zoom.us", "paypal.com", "wordpress.org", "etsy.com", "quora.com",
    "imdb.com", "bbc.com", "cnn.com", "nytimes.com", "forbes.com",
    "espn.com", "tripadvisor.com", "airbnb.com", "ebay.com", "spotify.com",
    "tumblr.com", "slack.com", "salesforce.com", "paypal.com", "dell.com",
    "ikea.com", "nasa.gov", "ted.com", "medium.com", "huffpost.com",
    "mozilla.org", "bbc.co.uk", "washingtonpost.com", "usatoday.com", "buzzfeed.com"
]

domains = domains_50 * 4

CONCURRENT_TASKS = 20  

async def limited_analyze(sem, domain):
    async with sem:
        try:
            logging.info(f"Починаємо аналіз: {domain}")
            result = await analyze_domain(domain)
            logging.info(f"Завершено аналіз: {domain}")
            return domain, result
        except Exception as e:
            logging.error(f"Помилка аналізу {domain}: {e}")
            return domain, None

async def stress_test(domains):
    sem = asyncio.Semaphore(CONCURRENT_TASKS)
    tasks = [limited_analyze(sem, domain) for domain in domains]
    results = await asyncio.gather(*tasks)
    return results

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    results = asyncio.run(stress_test(domains))
    logging.info(f"\nОброблено {len(results)} доменів")

