import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify, render_template
import joblib
import numpy as np
from src.logger import logging
from src.exception import CustomException

app = Flask(__name__)

# load model and feature list
MODEL_PATH   = os.path.join(os.path.dirname(__file__), '..', 'model', 'phishing_model.pkl')
FEATURES_PATH = os.path.join(os.path.dirname(__file__), '..', 'model', 'feature_cols.pkl')

model        = joblib.load(MODEL_PATH)
print(f'Model type: {type(model).__name__}')
feature_cols = joblib.load(FEATURES_PATH)
print(f'Feature cols: {feature_cols}')
print(f'Number of features: {len(feature_cols)}')

# plain English explanations for each feature
FEATURE_EXPLANATIONS = {
    'ip':                        ('IP Address in URL',            'URL uses a raw IP address instead of a domain name, a common phishing technique.',        'high'),
    'phish_hints':               ('Suspicious Keywords',          'URL contains words like "login", "verify", or "secure" commonly used in phishing.',        'high'),
    'prefix_suffix':             ('Hyphen in Domain',             'Domain contains a hyphen, often used to mimic legitimate brands (e.g. paypal-verify.com).','high'),
    'ratio_digits_url':          ('High Digit Ratio',             'URL contains an unusually high proportion of numbers.',                                     'medium'),
    'ratio_digits_host':         ('Digits in Hostname',           'Hostname contains a high ratio of digits, unusual for legitimate domains.',                'medium'),
    'tld_in_subdomain':          ('TLD in Subdomain',             'A top-level domain (.com, .net) appears in the subdomain , a known phishing trick.',        'high'),
    'length_url':                ('Long URL',                     'URL is unusually long, attackers pad URLs to hide the malicious destination.',             'medium'),
    'nb_dots':                   ('Excessive Dots',               'URL contains many dots, may indicate subdomain abuse.',                                    'medium'),
    'nb_slash':                  ('Excessive Slashes',            'URL has an unusually deep path structure.',                                                 'medium'),
    'nb_qm':                     ('Multiple Query Strings',       'URL contains multiple question marks, unusual for legitimate sites.',                      'low'),
    'nb_eq':                     ('Multiple Equal Signs',         'URL contains multiple equal signs in query parameters.',                                    'low'),
    'nb_and':                    ('Multiple Ampersands',          'URL contains many parameters, may be used to obfuscate the true destination.',             'low'),
    'nb_com':                    ('Multiple .com Occurrences',    'URL contains .com more than once, often used to trick users (e.g. paypal.com.evil.com).',  'high'),
    'nb_www':                    ('Missing www',                  'URL does not use www, phishing sites often skip it.',                                      'low'),
    'shortest_word_host':        ('Very Short Words in Hostname', 'Hostname contains unusually short words, may indicate a randomly generated domain.',       'low'),
    'longest_word_path':         ('Long Words in Path',           'URL path contains unusually long words.',                                                   'low'),
    'longest_words_raw':         ('Long Raw Words',               'URL contains very long character sequences.',                                               'low'),
    'length_hostname':           ('Long Hostname',                'Hostname is unusually long.',                                                               'medium'),
    'avg_word_path':             ('Long Average Path Words',      'Average word length in the URL path is unusually high.',                                    'low'),
    'avg_word_host':             ('Long Average Host Words',      'Average word length in the hostname is unusually high.',                                    'low'),
    'length_words_raw':          ('High Total Word Length',       'Total character length of all words in the URL is unusually high.',                        'low'),
    'avg_words_raw':             ('High Average Word Length',     'Average word length across the entire URL is high.',                                        'low'),
    'domain_age':                ('New Domain',                   'Domain was registered recently, phishing domains are typically brand new.',                'high'),
    'domain_registration_length':('Short Registration Period',    'Domain is registered for a short period, phishing domains are rarely registered long-term.','medium'),
}

# thresholds, feature value must exceed these to be flagged
THRESHOLDS = {
    'ip':                         0,
    'phish_hints':                0,
    'prefix_suffix':              0,
    'tld_in_subdomain':           0,
    'ratio_digits_url':           0.1,
    'ratio_digits_host':          0.1,
    'length_url':                 75,
    'nb_dots':                    4,
    'nb_slash':                   5,
    'nb_qm':                      1,
    'nb_eq':                      2,
    'nb_and':                     2,
    'nb_com':                     1,
    'nb_www':                    -1,   # flag if nb_www == 0
    'shortest_word_host':        -1,   # skip
    'longest_word_path':          15,
    'longest_words_raw':          20,
    'length_hostname':            20,
    'avg_word_path':              8,
    'avg_word_host':              8,
    'length_words_raw':           40,
    'avg_words_raw':              7,
    'domain_age':                 365,  # flag if domain < 1 year old
    'domain_registration_length': 365,
}


def get_triggered_features(features_dict):
    triggered = []
    for feature, value in features_dict.items():
        if feature not in FEATURE_EXPLANATIONS:
            continue
        threshold = THRESHOLDS.get(feature, -1)
        flagged = False

        if feature == 'nb_www':
            flagged = (value == 0)
        elif feature == 'domain_age':
            flagged = (0 < value < threshold)
        elif feature == 'domain_registration_length':
            flagged = (0 < value < threshold)
        else:
            flagged = (value > threshold)

        if flagged:
            name, description, severity = FEATURE_EXPLANATIONS[feature]
            triggered.append({
                'name':        name,
                'description': description,
                'severity':    severity,
            })

    # sort by severity
    order = {'high': 0, 'medium': 1, 'low': 2}
    triggered.sort(key=lambda x: order.get(x['severity'], 3))
    return triggered


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        url  = data.get('url', '').strip()

        if not url:
            return jsonify({'error': 'No URL provided.'}), 400

        logging.info(f'Predicting for URL: {url}')

        from src.feature_extractor import get_all_features, FEATURE_COLS
        features_list = get_all_features(url)
        features_dict = dict(zip(FEATURE_COLS, features_list))
        print(f'DEBUG features for {url}:')
        for f, v in features_dict.items():
            print(f'  {f:<35} {v}')

        prediction   = model.predict([features_list])[0]
        probability  = model.predict_proba([features_list])[0]
        print(f'DEBUG - prediction: {prediction}, prob[0]: {probability[0]:.4f}, prob[1]: {probability[1]:.4f}')
        confidence = float(probability[1]) 

        verdict  = 'PHISHING' if prediction == 1 else 'LEGITIMATE'
        triggered = get_triggered_features(features_dict)

        logging.info(f'Result: {verdict} ({confidence:.2%})')

        return jsonify({
            'verdict':    verdict,
            'confidence': round(confidence, 4),
            'features':   triggered,
        })

    except Exception as e:
        raise CustomException(e, sys)


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))