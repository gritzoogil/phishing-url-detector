import re
import sys
from urllib.parse import urlparse
from datetime import datetime

from src.logger import logging
from src.exception import CustomException

FEATURE_COLS = [
    'ratio_digits_url', 'phish_hints', 'ip', 'nb_qm',
    'length_url', 'nb_slash', 'length_hostname', 'nb_eq',
    'ratio_digits_host', 'shortest_word_host', 'prefix_suffix',
    'longest_word_path', 'tld_in_subdomain', 'nb_dots',
    'longest_words_raw', 'avg_word_path', 'avg_word_host',
    'length_words_raw', 'nb_and', 'avg_words_raw', 'nb_com',
    'domain_registration_length', 'domain_age', 'nb_www'
]

PHISH_HINTS = [
    'login', 'verify', 'secure', 'account', 'update',
    'banking', 'confirm', 'signin', 'password', 'credential',
    'paypal', 'ebay', 'amazon', 'apple', 'microsoft'
]

COMMON_TLDS = ['com', 'net', 'org', 'gov', 'edu']


def extract_url_features(url: str) -> dict:
    try:
        logging.info(f'Extracting URL features for: {url}')

        parsed   = urlparse(url)
        hostname = parsed.netloc.split(':')[0]
        path     = parsed.path

        url_words  = [w for w in re.split(r'[.\-/_?=&]', url)  if w]
        host_words = [w for w in re.split(r'[.\-]',      hostname) if w]
        path_words = [w for w in re.split(r'[.\-/_]',    path)   if w]

        # ratio_digits_url
        digits = sum(c.isdigit() for c in url)
        alpha  = sum(c.isalpha() for c in url)
        ratio_digits_url = digits / (digits + alpha) if (digits + alpha) > 0 else 0

        # phish_hints
        phish_hints = sum(h in url.lower() for h in PHISH_HINTS)

        # ip
        ip = 1 if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', hostname) else 0

        # ratio_digits_host
        hd = sum(c.isdigit() for c in hostname)
        ha = sum(c.isalpha() for c in hostname)
        ratio_digits_host = hd / (hd + ha) if (hd + ha) > 0 else 0

        # tld_in_subdomain
        subdomains = hostname.split('.')[:-2]
        tld_in_subdomain = 1 if any(t in subdomains for t in COMMON_TLDS) else 0

        features = {
            'ratio_digits_url':    ratio_digits_url,
            'phish_hints':         phish_hints,
            'ip':                  ip,
            'nb_qm':               url.count('?'),
            'length_url':          len(url),
            'nb_slash':            url.count('/'),
            'length_hostname':     len(hostname),
            'nb_eq':               url.count('='),
            'ratio_digits_host':   ratio_digits_host,
            'shortest_word_host':  min((len(w) for w in host_words), default=0),
            'prefix_suffix':       1 if '-' in hostname else 0,
            'longest_word_path':   max((len(w) for w in path_words), default=0),
            'tld_in_subdomain':    tld_in_subdomain,
            'nb_dots':             url.count('.'),
            'longest_words_raw':   max((len(w) for w in url_words), default=0),
            'avg_word_path':       sum(len(w) for w in path_words) / len(path_words) if path_words else 0,
            'avg_word_host':       sum(len(w) for w in host_words) / len(host_words) if host_words else 0,
            'length_words_raw':    sum(len(w) for w in url_words),
            'nb_and':              url.count('&'),
            'avg_words_raw':       sum(len(w) for w in url_words) / len(url_words) if url_words else 0,
            'nb_com':              url.count('.com'),
            'nb_www':              url.count('www.'),
        }

        logging.info('URL features extracted successfully')
        return features

    except Exception as e:
        raise CustomException(e, sys)


def extract_whois_features(url: str) -> dict:
    features = {
        'domain_age': -1,
        'domain_registration_length': -1
    }

    try:
        import whois

        parsed   = urlparse(url)
        hostname = parsed.netloc.split(':')[0]
        domain   = '.'.join(hostname.split('.')[-2:])

        logging.info(f'Fetching WHOIS for: {domain}')

        w = whois.whois(domain)

        creation_date   = w.creation_date
        expiration_date = w.expiration_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        # strip timezone info if present to avoid naive/aware mismatch
        if creation_date:
            if hasattr(creation_date, 'tzinfo') and creation_date.tzinfo is not None:
                creation_date = creation_date.replace(tzinfo=None)
            features['domain_age'] = (datetime.now() - creation_date).days

        if creation_date and expiration_date:
            if hasattr(expiration_date, 'tzinfo') and expiration_date.tzinfo is not None:
                expiration_date = expiration_date.replace(tzinfo=None)
            features['domain_registration_length'] = (expiration_date - creation_date).days

        logging.info('WHOIS features extracted successfully')

    except Exception as e:
        logging.warning(f'WHOIS lookup failed for {url}: {str(e)}. Using -1 as fallback.')

    return features


def get_all_features(url: str) -> list:
    try:
        logging.info(f'Starting full feature extraction for: {url}')

        features = extract_url_features(url)
        features.update(extract_whois_features(url))

        result = [features[col] for col in FEATURE_COLS]

        logging.info('Full feature extraction complete')
        return result

    except Exception as e:
        raise CustomException(e, sys)