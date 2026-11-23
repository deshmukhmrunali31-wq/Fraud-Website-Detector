from flask import Flask, request, jsonify, send_from_directory # type: ignore
import whois # type: ignore
import ssl
import socket
from urllib.parse import urlparse
from flask_cors import CORS # type: ignore
import logging
import time
from datetime import datetime, timedelta
from difflib import SequenceMatcher

# Set up logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__, static_folder='../frontend/fake/build', static_url_path='')
CORS(app, resources={r"/*": {"origins": "*"}})  # Allow all origins for testing

# Cache for WHOIS results to avoid rate limiting
whois_cache = {}
CACHE_DURATION = timedelta(hours=24)

# Trusted domains that bypass WHOIS check if it fails
TRUSTED_DOMAINS = [
    'google.com', 'facebook.com', 'amazon.com', 'microsoft.com', 
    'apple.com', 'netflix.com', 'twitter.com', 'instagram.com',
    'linkedin.com', 'youtube.com', 'reddit.com', 'wikipedia.org',
    'github.com', 'stackoverflow.com', 'medium.com', 'spotify.com'
]

# Legitimate domains for misspelling detection
LEGITIMATE_DOMAINS = [
    'google', 'facebook', 'twitter', 'instagram', 'linkedin', 'amazon',
    'netflix', 'youtube', 'microsoft', 'apple', 'paypal', 'walmart',
    'github', 'stackoverflow', 'reddit', 'spotify', 'hulu', 'ebay',
    'yahoo', 'bing', 'duckduckgo', 'whatsapp', 'snapchat', 'tiktok',
    'pinterest', 'twitch', 'discord', 'slack', 'zoom', 'dropbox',
    'wordpress', 'shopify', 'etsy', 'bestbuy', 'target', 'costco',
    'homedepot', 'lowes', 'ikea', 'tesla', 'spacex', 'adobe', 'salesforce'
]

@app.route("/")
def index():
    return send_from_directory(app.static_folder, 'index.html')

def get_domain(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    # Remove www prefix if present
    if domain.startswith('www.'):
        domain = domain[4:]
    # Remove port if present
    domain = domain.split(':')[0]
    return domain

def check_ssl_certificate(url):
    try:
        if not url.startswith('http'):
            url = 'https://' + url
        domain = get_domain(url)
        
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn.settimeout(5.0)  # Increased timeout
        conn.connect((domain, 443))
        ssl_info = conn.getpeercert()
        conn.close()
        
        # Additional SSL validation
        if ssl_info:
            # Check if certificate is expired
            expire_date = datetime.strptime(ssl_info['notAfter'], '%b %d %H:%M:%S %Y %Z')
            if expire_date < datetime.now():
                logging.debug(f"SSL certificate expired for {domain}")
                return False
            return True
        return False
    except Exception as e:
        logging.debug(f"SSL check failed for {url}: {str(e)}")
        return False

def check_misspelled_url(url):
    """
    Check if a URL is misspelled using fuzzy matching and common typo patterns
    """
    # Clean the URL
    clean_url = url.lower().replace('http://', '').replace('https://', '').replace('www.', '')
    
    # Extract the main domain (before first dot)
    main_domain = clean_url.split('.')[0]
    
    # Remove common suffixes that might appear in phishing URLs
    suffixes = ['login', 'secure', 'account', 'verify', 'signin', 'auth', 'help', 'support', 
                'security', 'verification', 'confirm', 'alert', 'notice', 'update', 'service']
    for suffix in suffixes:
        if main_domain.endswith(suffix):
            main_domain = main_domain[:-len(suffix)]
    
    # Remove common prefixes
    prefixes = ['my', 'your', 'get', 'go', 'www', 'mail', 'secure', 'login', 'signin']
    for prefix in prefixes:
        if main_domain.startswith(prefix):
            main_domain = main_domain[len(prefix):]
    
    # Check for exact matches first (legitimate)
    if main_domain in LEGITIMATE_DOMAINS:
        logging.debug(f"Exact match found for '{main_domain}' - legitimate")
        return True
    
    # Check for typos using fuzzy matching
    for legit_domain in LEGITIMATE_DOMAINS:
        # Calculate similarity ratio
        similarity = SequenceMatcher(None, main_domain, legit_domain).ratio()
        
        # If it's very similar but not exact (0.75 to 0.99), it's likely a typo
        if 0.75 < similarity < 1.0:
            logging.debug(f"Potential typo detected: '{main_domain}' vs '{legit_domain}' (similarity: {similarity})")
            return False
        
        # Check for character transpositions (like 'facebak' vs 'facebook')
        if len(main_domain) == len(legit_domain) and len(main_domain) > 3:
            diff_count = sum(1 for a, b in zip(main_domain, legit_domain) if a != b)
            # If only 1-2 characters are different, it's likely a typo
            if diff_count <= 2:
                logging.debug(f"Character transposition detected: '{main_domain}' vs '{legit_domain}' (diff: {diff_count})")
                return False
        
        # Check for common letter substitutions
        if len(main_domain) == len(legit_domain):
            substitutions = {
                'c': 'k', 'k': 'c', 's': 'z', 'z': 's', 'a': 'e', 'e': 'a',
                'i': 'y', 'y': 'i', 'o': 'u', 'u': 'o', 'b': 'p', 'p': 'b',
                'd': 't', 't': 'd', 'f': 'v', 'v': 'f', 'm': 'n', 'n': 'm'
            }
            diff_positions = []
            for i, (a, b) in enumerate(zip(main_domain, legit_domain)):
                if a != b:
                    diff_positions.append((i, a, b))
            
            # Check if differences are common substitutions
            if len(diff_positions) <= 2:
                is_common_substitution = True
                for pos, a, b in diff_positions:
                    if a in substitutions and substitutions[a] != b:
                        if b in substitutions and substitutions[b] != a:
                            is_common_substitution = False
                            break
                if is_common_substitution and len(diff_positions) > 0:
                    logging.debug(f"Common substitution detected: '{main_domain}' vs '{legit_domain}'")
                    return False
    
    # Check for double letters (like 'ffacebook' or 'faceebook')
    for legit_domain in LEGITIMATE_DOMAINS:
        if len(main_domain) == len(legit_domain) + 1:
            # Check if it's a double letter typo
            for i in range(len(main_domain) - 1):
                if main_domain[i] == main_domain[i + 1]:  # Double letter found
                    # Remove the double letter and compare
                    temp_domain = main_domain[:i] + main_domain[i+1:]
                    if temp_domain == legit_domain:
                        logging.debug(f"Double letter typo detected: '{main_domain}' vs '{legit_domain}'")
                        return False
        
        # Check for missing letters
        if len(main_domain) == len(legit_domain) - 1:
            for i in range(len(legit_domain)):
                temp_domain = legit_domain[:i] + legit_domain[i+1:]
                if temp_domain == main_domain:
                    logging.debug(f"Missing letter typo detected: '{main_domain}' vs '{legit_domain}'")
                    return False
    
    # If no match found, it might be legitimate or completely different
    logging.debug(f"Domain '{main_domain}' passed misspelling check")
    return True

def check_https_protocol(url):
    return url.startswith('https://')

def check_domain_info(url):
    try:
        domain = get_domain(url)
        
        # Check cache first
        if domain in whois_cache:
            cache_time, result = whois_cache[domain]
            if datetime.now() - cache_time < CACHE_DURATION:
                logging.debug(f"Using cached WHOIS result for {domain}")
                return result
        
        logging.debug(f"Checking WHOIS for domain: {domain}")
        
        # Try with timeout and retry logic
        for attempt in range(2):  # 2 attempts
            try:
                domain_info = whois.whois(domain)
                if domain_info and domain_info.creation_date:
                    # Handle different date formats
                    creation_date = domain_info.creation_date
                    if isinstance(creation_date, list):
                        creation_date = creation_date[0]
                    
                    # Check if domain is too new (less than 30 days old)
                    if isinstance(creation_date, datetime):
                        age = datetime.now() - creation_date
                        if age.days < 30:
                            logging.debug(f"Domain {domain} is only {age.days} days old - suspicious")
                            whois_cache[domain] = (datetime.now(), False)
                            return False
                    
                    logging.debug(f"WHOIS successful for {domain}")
                    whois_cache[domain] = (datetime.now(), True)
                    return True
                break
            except Exception as e:
                logging.debug(f"WHOIS attempt {attempt + 1} failed for {domain}: {str(e)}")
                if attempt == 0:
                    time.sleep(1)  # Wait 1 second before retry
                else:
                    # Check if it's a trusted domain before failing
                    if domain in TRUSTED_DOMAINS:
                        logging.debug(f"{domain} is a trusted domain, overriding WHOIS failure")
                        whois_cache[domain] = (datetime.now(), True)
                        return True
                    whois_cache[domain] = (datetime.now(), False)
                    return False
        
        # If we get here, no creation_date found
        logging.debug(f"No creation date found for {domain}")
        whois_cache[domain] = (datetime.now(), False)
        return False
        
    except Exception as e:
        logging.debug(f"WHOIS check failed for {url}: {str(e)}")
        # Check if it's a trusted domain
        domain = get_domain(url)
        if domain in TRUSTED_DOMAINS:
            logging.debug(f"{domain} is a trusted domain, overriding WHOIS failure")
            return True
        return False

@app.route('/check-website', methods=['POST', 'GET'])
def check_website():
    # Handle GET requests for testing
    if request.method == 'GET':
        url = request.args.get('url')
    else:
        data = request.get_json()
        url = data.get('url') if data else None

    logging.debug(f"Received request for URL: {url}")

    if not url:
        return jsonify({"message": "Invalid URL", "isLegit": False}), 400

    # Validate URL format
    if not url.startswith(('http://', 'https://')):
        return jsonify({"message": "Please include http:// or https:// in the URL", "isLegit": False}), 200

    # Run all checks
    https_valid = check_https_protocol(url)
    ssl_valid = check_ssl_certificate(url)
    misspelled_url = check_misspelled_url(url)
    domain_valid = check_domain_info(url)

    logging.debug(f"Results - HTTPS: {https_valid}, SSL: {ssl_valid}, Misspelled: {misspelled_url}, Domain: {domain_valid}")

    # Determine if website is legitimate
    # For trusted domains, be more lenient with WHOIS check
    domain = get_domain(url)
    
    if domain in TRUSTED_DOMAINS:
        # Trusted domains only need HTTPS, SSL, and no misspelling
        if https_valid and ssl_valid and misspelled_url:
            response = {"message": "The website is legitimate (trusted domain).", "isLegit": True}
            logging.debug(f"Sending success response: {response}")
            return jsonify(response), 200
        elif not https_valid:
            response = {"message": "The website does not use HTTPS protocol.", "isLegit": False}
        elif not misspelled_url:  # Check misspelling BEFORE SSL for trusted domains
            response = {"message": "The website URL appears to be misspelled.", "isLegit": False}
        elif not ssl_valid:
            response = {"message": "The website does not have a valid SSL certificate.", "isLegit": False}
        else:
            response = {"message": "The website failed validation checks.", "isLegit": False}
        
        logging.debug(f"Sending error response: {response}")
        return jsonify(response), 200
    
    # For non-trusted domains, check in priority order: HTTPS -> Misspelled -> SSL -> Domain
    if https_valid and ssl_valid and misspelled_url and domain_valid:
        response = {"message": "The website is legitimate.", "isLegit": True}
        logging.debug(f"Sending success response: {response}")
        return jsonify(response), 200
    else:
        if not https_valid:
            response = {"message": "The website does not use HTTPS protocol.", "isLegit": False}
        elif not misspelled_url:  # Check misspelling BEFORE SSL
            response = {"message": "The website URL appears to be misspelled.", "isLegit": False}
        elif not ssl_valid:
            response = {"message": "The website does not have a valid SSL certificate.", "isLegit": False}
        elif not domain_valid:
            response = {"message": "The website domain information is suspicious or cannot be verified.", "isLegit": False}
        else:
            response = {"message": "The website failed validation checks.", "isLegit": False}
        
        logging.debug(f"Sending error response: {response}")
        return jsonify(response), 200

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for testing if server is running"""
    return jsonify({"status": "healthy", "message": "Server is running"}), 200

@app.route('/test-misspelled', methods=['POST'])
def test_misspelled():
    """Test endpoint specifically for misspelling detection"""
    data = request.get_json()
    url = data.get('url')
    
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    
    is_legitimate = check_misspelled_url(url)
    return jsonify({
        "url": url,
        "is_legitimate_spelling": is_legitimate,
        "message": "URL appears correctly spelled" if is_legitimate else "URL appears to be misspelled"
    }), 200

if __name__ == '__main__':
    print("=" * 60)
    print("🛡️  Fraud Detector Backend Server - Enhanced Version")
    print("=" * 60)
    print("📡 Server running on: http://localhost:5000")
    print("🏥 Health check: http://localhost:5000/health")
    print("🔍 Check website: http://localhost:5000/check-website")
    print("🧪 Test misspelled: http://localhost:5000/test-misspelled")
    print("=" * 60)
    print("🎯 Priority Order for Checks:")
    print("   1️⃣  HTTPS Protocol")
    print("   2️⃣  Misspelled URL (NOW CHECKED BEFORE SSL)") 
    print("   3️⃣  SSL Certificate")
    print("   4️⃣  Domain Information (WHOIS)")
    print("=" * 60)
    print("✅ For https://facebak.com - Will show MISSPELLED warning first!")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=5000)