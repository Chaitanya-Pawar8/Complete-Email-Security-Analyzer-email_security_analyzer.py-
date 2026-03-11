"""
AI-Powered Email Security Analyzer
Complete SOC-grade email threat detection system
"""

import re
import dns.resolver
import requests
import socket
import whois
import tldextract
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from urllib.parse import urlparse, unquote
from datetime import datetime, timedelta
from difflib import SequenceMatcher
from bs4 import BeautifulSoup
import nltk
from nltk.tokenize import sent_tokenize
from transformers import pipeline
import json
from flask import Flask, render_template, request, jsonify
import configparser
from typing import Dict, List, Tuple, Any
import logging

# Download NLTK data if needed
try:
    nltk.data.find('tokenizers/punkt')
except LookupError:
    nltk.download('punkt')

# ==================== CONFIGURATION ====================
class Config:
    """Configuration settings for Email Security Analyzer"""
    
    # Risk scoring weights
    RISK_WEIGHTS = {
        'header_anomalies': 20,
        'spf_fail': 15,
        'dkim_fail': 15,
        'dmarc_fail': 15,
        'suspicious_domain': 25,
        'malicious_links': 30,
        'dangerous_attachments': 35,
        'social_engineering': 20,
        'spoofing_attempt': 25,
        'new_domain': 10
    }
    
    # Classification thresholds
    CLASSIFICATION_THRESHOLDS = {
        'safe': 20,
        'suspicious': 40,
        'phishing': 70,
        'malicious': 85
    }
    
    # Suspicious TLDs
    SUSPICIOUS_TLDS = [
        '.tk', '.ml', '.ga', '.cf', '.xyz', '.top', 
        '.club', '.online', '.site', '.web', '.work'
    ]
    
    # Dangerous attachment extensions
    DANGEROUS_EXTENSIONS = {
        '.exe': 'Executable file - can run malicious code',
        '.scr': 'Screensaver file - can execute code',
        '.js': 'JavaScript file - can execute malicious scripts',
        '.vbs': 'VBScript file - can execute commands',
        '.docm': 'Word document with macros - can contain malicious macros',
        '.xlsm': 'Excel workbook with macros - can contain malicious macros',
        '.zip': 'Compressed archive - may contain malicious files',
        '.rar': 'Compressed archive - may contain malicious files',
        '.7z': 'Compressed archive - may contain malicious files',
        '.jar': 'Java archive - can execute code',
        '.bat': 'Batch file - can execute commands',
        '.cmd': 'Command file - can execute commands',
        '.ps1': 'PowerShell script - can execute commands',
        '.hta': 'HTML application - can execute code'
    }
    
    # Common brand domains for typosquatting detection
    BRAND_DOMAINS = [
        'paypal', 'google', 'facebook', 'amazon', 'apple',
        'microsoft', 'netflix', 'linkedin', 'twitter', 'instagram',
        'bankofamerica', 'chase', 'wellsfargo', 'citibank', 'hsbc'
    ]
    
    # Social engineering keywords
    URGENCY_KEYWORDS = [
        'immediate action', 'urgent', 'act now', 'limited time',
        'expires today', '24 hours', 'account suspended', 'verify now',
        'click here immediately', 'don\'t wait', 'hurry', 'deadline'
    ]
    
    THREAT_KEYWORDS = [
        'suspended', 'terminated', 'blocked', 'unauthorized access',
        'security breach', 'hacked', 'compromised', 'legal action',
        'lawsuit', 'police', 'fbi', 'investigation', 'arrest warrant'
    ]
    
    AUTHORITY_KEYWORDS = [
        'security team', 'administrator', 'support team', 'help desk',
        'account manager', 'customer service', 'fraud department',
        'security department', 'it department', 'system admin'
    ]
    
    CREDENTIAL_KEYWORDS = [
        'password', 'username', 'login', 'sign in', 'credential',
        'verify account', 'confirm identity', 'update payment',
        'bank details', 'credit card', 'ssn', 'social security'
    ]
    
    # URL shorteners
    URL_SHORTENERS = [
        'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd',
        'buff.ly', 'adf.ly', 'shorte.st', 'bc.vc', 't.co',
        'lnkd.in', 'db.tt', 'qr.ae', 'cur.lv', 'bitly.com',
        'tiny.cc', 'tr.im', 'v.gd', 'cli.gs', 'pic.gd'
    ]


# ==================== HEADER ANALYZER ====================
class HeaderAnalyzer:
    """Email Header Analysis Module"""
    
    def __init__(self):
        self.results = {
            'spf_status': 'unknown',
            'dkim_status': 'unknown',
            'dmarc_status': 'unknown',
            'received_chain': [],
            'forged_domain_detected': False,
            'ip_anomalies': [],
            'header_manipulations': [],
            'suspicious_elements': []
        }
    
    def analyze(self, headers_text: str, msg) -> Dict:
        """Main analysis method"""
        self._check_authentication_results(msg)
        self._analyze_received_chain(msg)
        self._check_for_forged_domain(msg)
        self._check_ip_anomalies(headers_text)
        self._check_header_manipulations(headers_text)
        return self.results
    
    def _check_authentication_results(self, msg):
        """Check SPF, DKIM, DMARC status"""
        auth_results = msg.get('Authentication-Results', '')
        
        # Check SPF
        spf_match = re.search(r'spf=(\w+)', auth_results, re.IGNORECASE)
        if spf_match:
            self.results['spf_status'] = spf_match.group(1)
        else:
            self._check_spf_dns(msg)
        
        # Check DKIM
        dkim_match = re.search(r'dkim=(\w+)', auth_results, re.IGNORECASE)
        if dkim_match:
            self.results['dkim_status'] = dkim_match.group(1)
        
        # Check DMARC
        dmarc_match = re.search(r'dmarc=(\w+)', auth_results, re.IGNORECASE)
        if dmarc_match:
            self.results['dmarc_status'] = dmarc_match.group(1)
    
    def _check_spf_dns(self, msg):
        """Perform SPF check via DNS"""
        try:
            from_domain = parseaddr(msg.get('From', ''))[1].split('@')[-1]
            answers = dns.resolver.resolve(from_domain, 'TXT')
            
            for rdata in answers:
                if 'v=spf1' in str(rdata):
                    self.results['spf_status'] = 'pass'
                    return
            self.results['spf_status'] = 'none'
        except:
            self.results['spf_status'] = 'error'
    
    def _analyze_received_chain(self, msg):
        """Analyze Received headers for anomalies"""
        received_headers = msg.get_all('Received', [])
        
        for i, received in enumerate(received_headers):
            hop_info = {
                'hop': i + 1,
                'from': self._extract_from_server(received),
                'by': self._extract_by_server(received),
                'with': self._extract_with_protocol(received),
                'date': self._extract_date(received),
                'suspicious': False
            }
            
            # Check for suspicious patterns
            if 'unknown' in hop_info['from'].lower() or 'localhost' in hop_info['from'].lower():
                hop_info['suspicious'] = True
                self.results['suspicious_elements'].append(f"Suspicious server in hop {i+1}")
            
            if hop_info['with'] and 'http' in hop_info['with'].lower():
                hop_info['suspicious'] = True
                self.results['suspicious_elements'].append(f"Unusual protocol in hop {i+1}")
            
            self.results['received_chain'].append(hop_info)
    
    def _check_for_forged_domain(self, msg):
        """Check for domain forgery in From header"""
        from_header = msg.get('From', '')
        return_path = msg.get('Return-Path', '')
        reply_to = msg.get('Reply-To', '')
        
        # Extract domains
        from_domain = parseaddr(from_header)[1].split('@')[-1] if '@' in from_header else ''
        return_domain = return_path.replace('>', '').replace('<', '').split('@')[-1] if '@' in return_path else ''
        reply_domain = parseaddr(reply_to)[1].split('@')[-1] if '@' in reply_to else ''
        
        # Check for mismatches
        if from_domain and return_domain and from_domain != return_domain:
            self.results['forged_domain_detected'] = True
            self.results['suspicious_elements'].append(
                f"From domain ({from_domain}) doesn't match Return-Path ({return_domain})"
            )
    
    def _check_ip_anomalies(self, headers_text):
        """Check for IP address anomalies in headers"""
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips = re.findall(ip_pattern, headers_text)
        
        for ip in ips:
            if self._is_private_ip(ip):
                self.results['ip_anomalies'].append(f"Private IP detected: {ip}")
    
    def _check_header_manipulations(self, headers_text):
        """Check for header manipulation attempts"""
        # Check for duplicate headers
        header_counts = {}
        for line in headers_text.split('\n'):
            if ':' in line:
                header = line.split(':')[0].strip()
                header_counts[header] = header_counts.get(header, 0) + 1
        
        for header, count in header_counts.items():
            if count > 1 and header.lower() not in ['received', 'x-mailer']:
                self.results['header_manipulations'].append(f"Duplicate header: {header}")
        
        # Check for injection attempts
        injection_patterns = [
            r'\n.*bcc:', r'\n.*cc:', r'\n.*to:',
            r'%0a', r'%0d', r'\r\n\r\n'
        ]
        
        for pattern in injection_patterns:
            if re.search(pattern, headers_text, re.IGNORECASE):
                self.results['header_manipulations'].append("Header injection attempt detected")
                break
    
    def _extract_from_server(self, received):
        match = re.search(r'from\s+([^\s]+)', received, re.IGNORECASE)
        return match.group(1) if match else 'unknown'
    
    def _extract_by_server(self, received):
        match = re.search(r'by\s+([^\s]+)', received, re.IGNORECASE)
        return match.group(1) if match else 'unknown'
    
    def _extract_with_protocol(self, received):
        match = re.search(r'with\s+([^\s]+)', received, re.IGNORECASE)
        return match.group(1) if match else 'unknown'
    
    def _extract_date(self, received):
        match = re.search(r';\s*(.+)$', received)
        return match.group(1).strip() if match else 'unknown'
    
    def _is_private_ip(self, ip):
        try:
            parts = list(map(int, ip.split('.')))
            return (parts[0] == 10 or
                    (parts[0] == 172 and 16 <= parts[1] <= 31) or
                    (parts[0] == 192 and parts[1] == 168) or
                    parts[0] == 127)
        except:
            return False


# ==================== DOMAIN ANALYZER ====================
class DomainAnalyzer:
    """Domain & Sender Analysis Module"""
    
    def __init__(self):
        self.results = {
            'typosquatting_detected': [],
            'spoofed_domains': [],
            'new_domains': [],
            'domain_mismatches': [],
            'suspicious_tlds': [],
            'risk_indicators': []
        }
    
    def analyze(self, msg) -> Dict:
        """Main analysis method"""
        domains = self._extract_domains(msg)
        
        for domain in domains:
            self._check_typosquatting(domain)
            self._check_domain_age(domain)
            self._check_suspicious_tld(domain)
        
        self._check_sender_mismatch(msg)
        return self.results
    
    def _extract_domains(self, msg):
        """Extract all domains from email headers"""
        domains = set()
        
        headers_to_check = ['From', 'Return-Path', 'Reply-To']
        for header in headers_to_check:
            value = msg.get(header, '')
            if '@' in value:
                domain = value.split('@')[-1].strip('>').strip()
                if domain:
                    domains.add(domain)
        
        return list(domains)
    
    def _check_typosquatting(self, domain):
        """Check for typosquatting attempts"""
        extracted = tldextract.extract(domain)
        domain_name = extracted.domain.lower()
        
        for brand in Config.BRAND_DOMAINS:
            if domain_name != brand and self._is_similar(domain_name, brand):
                self.results['typosquatting_detected'].append({
                    'domain': domain,
                    'imitated_brand': brand,
                    'similarity': self._calculate_similarity(domain_name, brand)
                })
                self.results['risk_indicators'].append(
                    f"Typosquatting detected: {domain} imitates {brand}"
                )
    
    def _check_domain_age(self, domain):
        """Check if domain is newly registered"""
        try:
            domain_info = whois.whois(domain)
            creation_date = domain_info.creation_date
            
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date:
                age = datetime.now() - creation_date
                if age.days < 30:
                    self.results['new_domains'].append({
                        'domain': domain,
                        'creation_date': creation_date.strftime('%Y-%m-%d'),
                        'age_days': age.days
                    })
                    self.results['risk_indicators'].append(
                        f"Suspicious new domain: {domain} (created {age.days} days ago)"
                    )
        except:
            self.results['risk_indicators'].append(
                f"Unable to verify domain age: {domain}"
            )
    
    def _check_suspicious_tld(self, domain):
        """Check for suspicious TLDs"""
        extracted = tldextract.extract(domain)
        tld = '.' + extracted.suffix
        
        if tld in Config.SUSPICIOUS_TLDS:
            self.results['suspicious_tlds'].append({
                'domain': domain,
                'tld': tld
            })
            self.results['risk_indicators'].append(
                f"Suspicious TLD used: {tld} in {domain}"
            )
    
    def _check_sender_mismatch(self, msg):
        """Check for mismatches between display name and domain"""
        from_header = msg.get('From', '')
        
        match = re.match(r'"?([^"<]+)"?\s*<([^>]+)>', from_header)
        if match:
            display_name = match.group(1).strip()
            email_addr = match.group(2)
            
            if '@' in display_name:
                display_domain = display_name.split('@')[-1]
                actual_domain = email_addr.split('@')[-1]
                
                if display_domain != actual_domain:
                    self.results['domain_mismatches'].append({
                        'display_domain': display_domain,
                        'actual_domain': actual_domain
                    })
                    self.results['risk_indicators'].append(
                        f"Domain mismatch: Display name uses {display_domain} but email is from {actual_domain}"
                    )
    
    def _is_similar(self, str1, str2, threshold=0.8):
        return self._calculate_similarity(str1, str2) > threshold
    
    def _calculate_similarity(self, str1, str2):
        return SequenceMatcher(None, str1, str2).ratio()


# ==================== LANGUAGE ANALYZER ====================
class LanguageAnalyzer:
    """Language & Social Engineering Detection Module"""
    
    def __init__(self):
        self.results = {
            'urgency_detected': [],
            'threat_language_detected': [],
            'authority_impersonation': [],
            'credential_harvesting': [],
            'suspicious_patterns': [],
            'sentiment_score': 0,
            'manipulation_indicators': []
        }
        
        # Initialize sentiment analyzer
        try:
            self.sentiment_analyzer = pipeline(
                "sentiment-analysis",
                model="distilbert-base-uncased-finetuned-sst-2-english",
                framework="pt"
            )
        except:
            self.sentiment_analyzer = None
    
    def analyze(self, body_text: str) -> Dict:
        """Main analysis method"""
        if not body_text:
            return self.results
        
        text_lower = body_text.lower()
        
        self._check_urgency(text_lower)
        self._check_threat_language(text_lower)
        self._check_authority_impersonation(text_lower)
        self._check_credential_harvesting(text_lower)
        self._check_suspicious_patterns(body_text)
        self._analyze_sentiment(body_text)
        
        return self.results
    
    def _check_urgency(self, text):
        for keyword in Config.URGENCY_KEYWORDS:
            if keyword in text:
                self.results['urgency_detected'].append(keyword)
                self.results['manipulation_indicators'].append(
                    f"Urgency tactic detected: '{keyword}'"
                )
    
    def _check_threat_language(self, text):
        for keyword in Config.THREAT_KEYWORDS:
            if keyword in text:
                self.results['threat_language_detected'].append(keyword)
                self.results['manipulation_indicators'].append(
                    f"Threat language detected: '{keyword}'"
                )
    
    def _check_authority_impersonation(self, text):
        for keyword in Config.AUTHORITY_KEYWORDS:
            if keyword in text:
                self.results['authority_impersonation'].append(keyword)
                self.results['manipulation_indicators'].append(
                    f"Authority impersonation detected: '{keyword}'"
                )
    
    def _check_credential_harvesting(self, text):
        for keyword in Config.CREDENTIAL_KEYWORDS:
            if keyword in text:
                self.results['credential_harvesting'].append(keyword)
                self.results['manipulation_indicators'].append(
                    f"Credential harvesting attempt: '{keyword}'"
                )
        
        login_patterns = [
            r'login.*account',
            r'sign.*in.*verify',
            r'confirm.*password',
            r'update.*payment.*information',
            r'verify.*identity'
        ]
        
        for pattern in login_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                self.results['suspicious_patterns'].append(f"Login form pattern: {pattern}")
    
    def _check_suspicious_patterns(self, text):
        if re.search(r'!{3,}', text):
            self.results['suspicious_patterns'].append("Excessive exclamation marks")
        
        sentences = sent_tokenize(text)
        for sent in sentences:
            if len(sent) > 10 and sent.isupper():
                self.results['suspicious_patterns'].append("ALL CAPS sentence detected")
                break
        
        grammar_issues = [
            r'\b(ya?ou?r?)\b.*\b(accoun?t?)\b',
            r'\b(plae?se?)\b',
            r'\b(verif?y?)\b.*\b(now|today)\b'
        ]
        
        for pattern in grammar_issues:
            if re.search(pattern, text, re.IGNORECASE):
                self.results['suspicious_patterns'].append("Poor grammar/spelling detected")
                break
    
    def _analyze_sentiment(self, text):
        if not self.sentiment_analyzer:
            self.results['sentiment_score'] = 0
            return
        
        try:
            if len(text) > 512:
                text = text[:512]
            
            result = self.sentiment_analyzer(text)[0]
            
            if result['label'] == 'NEGATIVE':
                self.results['sentiment_score'] = -result['score']
            else:
                self.results['sentiment_score'] = result['score']
            
            if self.results['sentiment_score'] < -0.7:
                self.results['manipulation_indicators'].append(
                    "Strong negative sentiment detected - possible fear tactic"
                )
        except:
            self.results['sentiment_score'] = 0


# ==================== LINK ANALYZER ====================
class LinkAnalyzer:
    """Link Analysis Module"""
    
    def __init__(self):
        self.results = {
            'total_links': 0,
            'suspicious_domains': [],
            'url_shorteners': [],
            'redirect_chains': [],
            'phishing_pages': [],
            'mismatched_links': [],
            'analyzed_links': []
        }
    
    def analyze(self, body_text: str) -> Dict:
        """Main analysis method"""
        if not body_text:
            return self.results
        
        links = self._extract_links(body_text)
        self.results['total_links'] = len(links)
        
        for link in links:
            link_info = self._analyze_link(link)
            self.results['analyzed_links'].append(link_info)
            
            if link_info['is_shortener']:
                self.results['url_shorteners'].append(link)
            
            if link_info['suspicious_domain']:
                self.results['suspicious_domains'].append(link)
            
            if link_info.get('display_mismatch'):
                self.results['mismatched_links'].append(link_info)
            
            redirects = self._check_redirects(link)
            if redirects:
                self.results['redirect_chains'].append({
                    'original': link,
                    'chain': redirects
                })
        
        return self.results
    
    def _extract_links(self, text):
        url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s<>"\'(){}|\\^`\[\]]*'
        urls = re.findall(url_pattern, text)
        
        if '<a' in text or '<A' in text:
            soup = BeautifulSoup(text, 'html.parser')
            for link in soup.find_all('a'):
                href = link.get('href')
                if href and href.startswith(('http://', 'https://')):
                    urls.append(href)
        
        return list(set(urls))
    
    def _analyze_link(self, url):
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        if domain.startswith('www.'):
            domain = domain[4:]
        
        extracted = tldextract.extract(domain)
        base_domain = f"{extracted.domain}.{extracted.suffix}"
        
        link_info = {
            'url': url,
            'domain': domain,
            'base_domain': base_domain,
            'path': parsed.path,
            'is_shortener': self._is_shortener(domain),
            'suspicious_domain': self._is_suspicious_domain(domain),
            'display_mismatch': False,
            'has_ip': self._has_ip_address(domain),
            'suspicious_tld': self._has_suspicious_tld(domain),
            'risk_level': 'low'
        }
        
        if '%' in url and re.search(r'%[0-9a-f]{2}', url, re.IGNORECASE):
            link_info['encoded_chars'] = True
        
        if link_info['is_shortener'] or link_info['suspicious_domain']:
            link_info['risk_level'] = 'medium'
        if link_info['has_ip'] or link_info['suspicious_tld']:
            link_info['risk_level'] = 'high'
        
        return link_info
    
    def _check_redirects(self, url):
        try:
            redirects = []
            current_url = url
            visited = set()
            
            for _ in range(5):
                if current_url in visited:
                    break
                visited.add(current_url)
                
                response = requests.head(
                    current_url,
                    allow_redirects=False,
                    timeout=5,
                    headers={'User-Agent': 'Mozilla/5.0'}
                )
                
                if response.status_code in [301, 302, 303, 307, 308]:
                    next_url = response.headers.get('Location')
                    if next_url:
                        redirects.append({
                            'from': current_url,
                            'to': next_url,
                            'status': response.status_code
                        })
                        current_url = next_url
                    else:
                        break
                else:
                    break
            
            return redirects if redirects else None
        except:
            return None
    
    def _is_shortener(self, domain):
        return any(shortener in domain for shortener in Config.URL_SHORTENERS)
    
    def _is_suspicious_domain(self, domain):
        suspicious_patterns = [
            r'secure-.*\.com',
            r'account-.*\.com',
            r'verify-.*\.com',
            r'login-.*\.com',
            r'update-.*\.com'
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, domain, re.IGNORECASE):
                return True
        return False
    
    def _has_ip_address(self, domain):
        ip_pattern = r'^\d+\.\d+\.\d+\.\d+$'
        return bool(re.match(ip_pattern, domain))
    
    def _has_suspicious_tld(self, domain):
        for tld in Config.SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                return True
        return False


# ==================== ATTACHMENT ANALYZER ====================
class AttachmentAnalyzer:
    """Attachment Risk Analysis Module"""
    
    def __init__(self):
        self.results = {
            'has_attachments': False,
            'attachments': [],
            'dangerous_attachments': [],
            'risk_indicators': []
        }
    
    def analyze(self, msg) -> Dict:
        """Main analysis method"""
        if msg.is_multipart():
            self.results['has_attachments'] = True
            
            for part in msg.walk():
                if part.get_content_maintype() == 'multipart':
                    continue
                
                filename = part.get_filename()
                if filename:
                    attachment_info = self._analyze_attachment(filename, part)
                    self.results['attachments'].append(attachment_info)
                    
                    if attachment_info['dangerous']:
                        self.results['dangerous_attachments'].append(attachment_info)
                        self.results['risk_indicators'].append(
                            f"Dangerous attachment detected: {filename} - {attachment_info['reason']}"
                        )
        
        return self.results
    
    def _analyze_attachment(self, filename, part):
        """Analyze individual attachment"""
        name_lower = filename.lower()
        extension = None
        
        for ext in Config.DANGEROUS_EXTENSIONS.keys():
            if name_lower.endswith(ext):
                extension = ext
                break
        
        attachment_info = {
            'filename': filename,
            'size': len(part.get_payload(decode=True)) if part.get_payload(decode=True) else 0,
            'content_type': part.get_content_type(),
            'extension': extension,
            'dangerous': extension is not None,
            'reason': Config.DANGEROUS_EXTENSIONS.get(extension, 'Unknown risk') if extension else None
        }
        
        return attachment_info


# ==================== RISK SCORER ====================
class RiskScorer:
    """Risk Scoring System"""
    
    def __init__(self):
        self.total_score = 0
        self.threat_indicators = []
        self.classification = 'unknown'
    
    def calculate_risk(self, all_indicators: Dict) -> Tuple[int, str]:
        """Calculate risk score and determine classification"""
        score = 0
        self.threat_indicators = []
        
        # Header analysis scoring
        header = all_indicators.get('header', {})
        if header.get('forged_domain_detected'):
            score += 25
            self.threat_indicators.append("Domain forgery detected")
        
        if header.get('spf_status') == 'fail':
            score += 15
            self.threat_indicators.append("SPF check failed")
        
        if header.get('dkim_status') == 'fail':
            score += 15
            self.threat_indicators.append("DKIM check failed")
        
        if header.get('dmarc_status') == 'fail':
            score += 15
            self.threat_indicators.append("DMARC check failed")
        
        if len(header.get('header_manipulations', [])) > 0:
            score += 20
            self.threat_indicators.append("Header manipulation detected")
        
        # Domain analysis scoring
        domain = all_indicators.get('domain', {})
        if len(domain.get('typosquatting_detected', [])) > 0:
            score += 25
            self.threat_indicators.append("Typosquatting domain detected")
        
        if len(domain.get('new_domains', [])) > 0:
            score += 10
            self.threat_indicators.append("Newly registered suspicious domain")
        
        if len(domain.get('suspicious_tlds', [])) > 0:
            score += 10
            self.threat_indicators.append("Suspicious TLD detected")
        
        # Language analysis scoring
        language = all_indicators.get('language', {})
        if len(language.get('urgency_detected', [])) > 0:
            score += 10
            self.threat_indicators.append("Urgency tactics detected")
        
        if len(language.get('threat_language_detected', [])) > 0:
            score += 15
            self.threat_indicators.append("Threat language detected")
        
        if len(language.get('credential_harvesting', [])) > 0:
            score += 20
            self.threat_indicators.append("Credential harvesting attempt")
        
        # Link analysis scoring
        links = all_indicators.get('links', {})
        if links.get('total_links', 0) > 0:
            if len(links.get('suspicious_domains', [])) > 0:
                score += 20
                self.threat_indicators.append("Suspicious domains in links")
            
            if len(links.get('url_shorteners', [])) > 0:
                score += 10
                self.threat_indicators.append("URL shorteners used - possible obfuscation")
            
            if len(links.get('redirect_chains', [])) > 0:
                score += 15
                self.threat_indicators.append("Multiple redirects detected")
        
        # Attachment analysis scoring
        attachments = all_indicators.get('attachments', {})
        if len(attachments.get('dangerous_attachments', [])) > 0:
            score += 35
            self.threat_indicators.append("Dangerous attachments detected")
        
        # Determine classification
        if score < Config.CLASSIFICATION_THRESHOLDS['safe']:
            classification = 'Safe'
        elif score < Config.CLASSIFICATION_THRESHOLDS['suspicious']:
            classification = 'Suspicious'
        elif score < Config.CLASSIFICATION_THRESHOLDS['phishing']:
            classification = 'Phishing'
        else:
            classification = 'Malicious'
        
        self.total_score = min(score, 100)  # Cap at 100
        self.classification = classification
        
        return self.total_score, classification
    
    def get_threat_indicators(self):
        return self.threat_indicators
    
    def get_recommendation(self, classification):
        """Generate security recommendation based on classification"""
        recommendations = {
            'Safe': "This email appears legitimate. No immediate action required, but always stay vigilant.",
            'Suspicious': "Exercise caution with this email. Verify the sender through alternative channels before engaging.",
            'Phishing': "Likely phishing attempt. Do not click any links or open attachments. Report to security team.",
            'Malicious': "Confirmed malicious email. Do not interact. Delete immediately and report to IT security."
        }
        return recommendations.get(classification, "Unable to determine. Exercise extreme caution.")


# ==================== FLASK APPLICATION ====================
app = Flask(__name__)

@app.route('/')
def index():
    """Render main page"""
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>AI-Powered Email Security Analyzer</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                padding: 20px;
            }
            
            .container {
                max-width: 1200px;
                margin: 0 auto;
                background: white;
                border-radius: 10px;
                box-shadow: 0 10px 40px rgba(0,0,0,0.1);
                overflow: hidden;
            }
            
            .header {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 30px;
                text-align: center;
            }
            
            .header h1 {
                font-size: 2.5em;
                margin-bottom: 10px;
            }
            
            .header p {
                opacity: 0.9;
            }
            
            .input-section {
                padding: 30px;
            }
            
            .input-group {
                margin-bottom: 20px;
            }
            
            label {
                display: block;
                margin-bottom: 5px;
                font-weight: 600;
                color: #333;
            }
            
            textarea {
                width: 100%;
                padding: 15px;
                border: 2px solid #e0e0e0;
                border-radius: 5px;
                font-family: monospace;
                font-size: 14px;
                resize: vertical;
                transition: border-color 0.3s;
            }
            
            textarea:focus {
                outline: none;
                border-color: #667eea;
            }
            
            .analyze-btn {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                border: none;
                padding: 15px 30px;
                font-size: 16px;
                font-weight: 600;
                border-radius: 5px;
                cursor: pointer;
                width: 100%;
                transition: transform 0.3s, box-shadow 0.3s;
            }
            
            .analyze-btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4);
            }
            
            .analyze-btn:disabled {
                opacity: 0.5;
                cursor: not-allowed;
            }
            
            .loading {
                display: none;
                text-align: center;
                padding: 20px;
            }
            
            .loading-spinner {
                border: 4px solid #f3f3f3;
                border-top: 4px solid #667eea;
                border-radius: 50%;
                width: 40px;
                height: 40px;
                animation: spin 1s linear infinite;
                margin: 0 auto 10px;
            }
            
            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }
            
            .results-section {
                padding: 30px;
                background: #f9f9f9;
                border-top: 1px solid #e0e0e0;
            }
            
            .score-card {
                background: white;
                border-radius: 10px;
                padding: 20px;
                margin-bottom: 20px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            
            .risk-score {
                font-size: 48px;
                font-weight: bold;
                text-align: center;
                padding: 20px;
                border-radius: 10px;
                color: white;
            }
            
            .risk-score.safe { background: linear-gradient(135deg, #48c774 0%, #2ecc71 100%); }
            .risk-score.suspicious { background: linear-gradient(135deg, #f39c12 0%, #e67e22 100%); }
            .risk-score.phishing { background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); }
            .risk-score.malicious { background: linear-gradient(135deg, #c0392b 0%, #96281b 100%); }
            
            .classification {
                text-align: center;
                font-size: 24px;
                margin-top: 10px;
                font-weight: 600;
            }
            
            .threat-indicators {
                margin: 20px 0;
            }
            
            .indicator {
                background: #fff3cd;
                color: #856404;
                padding: 10px;
                margin: 5px 0;
                border-radius: 5px;
                border-left: 4px solid #ffc107;
            }
            
            .recommendation {
                background: #d4edda;
                color: #155724;
                padding: 15px;
                border-radius: 5px;
                border-left: 4px solid #28a745;
                font-weight: 500;
            }
            
            .details-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 20px;
                margin-top: 20px;
            }
            
            .detail-card {
                background: white;
                border-radius: 10px;
                padding: 20px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            
            .detail-card h3 {
                margin-bottom: 15px;
                color: #333;
                border-bottom: 2px solid #667eea;
                padding-bottom: 10px;
            }
            
            .detail-card ul {
                list-style: none;
            }
            
            .detail-card li {
                padding: 8px 0;
                border-bottom: 1px solid #f0f0f0;
                font-size: 14px;
            }
            
            .detail-card li:last-child {
                border-bottom: none;
            }
            
            .badge {
                display: inline-block;
                padding: 3px 8px;
                border-radius: 3px;
                font-size: 12px;
                font-weight: 600;
                margin-left: 5px;
            }
            
            .badge.danger { background: #e74c3c; color: white; }
            .badge.warning { background: #f39c12; color: white; }
            .badge.success { background: #2ecc71; color: white; }
            
            .error {
                background: #f8d7da;
                color: #721c24;
                padding: 15px;
                border-radius: 5px;
                margin: 20px 0;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔒 AI-Powered Email Security Analyzer</h1>
                <p>Paste your email headers and body below for instant threat analysis</p>
            </div>
            
            <div class="input-section">
                <div class="input-group">
                    <label for="headers">Email Headers</label>
                    <textarea id="headers" rows="10" placeholder="Paste email headers here..."></textarea>
                </div>
                
                <div class="input-group">
                    <label for="body">Email Body</label>
                    <textarea id="body" rows="10" placeholder="Paste email body here..."></textarea>
                </div>
                
                <button class="analyze-btn" onclick="analyzeEmail()">Analyze Email</button>
                
                <div class="loading" id="loading">
                    <div class="loading-spinner"></div>
                    <p>Analyzing email with AI... This may take a moment.</p>
                </div>
            </div>
            
            <div class="results-section" id="results" style="display: none;">
                <div class="score-card">
                    <div id="riskScore" class="risk-score"></div>
                    <div id="classification" class="classification"></div>
                </div>
                
                <div id="threatIndicators" class="threat-indicators"></div>
                <div id="recommendation" class="recommendation"></div>
                
                <div class="details-grid" id="details"></div>
            </div>
            
            <div id="error" class="error" style="display: none;"></div>
        </div>
        
        <script>
            async function analyzeEmail() {
                const headers = document.getElementById('headers').value;
                const body = document.getElementById('body').value;
                
                if (!headers && !body) {
                    alert('Please paste email headers or body to analyze');
                    return;
                }
                
                // Show loading
                document.getElementById('loading').style.display = 'block';
                document.getElementById('results').style.display = 'none';
                document.getElementById('error').style.display = 'none';
                
                try {
                    const response = await fetch('/analyze', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({ headers, body })
                    });
                    
                    const data = await response.json();
                    
                    if (data.success) {
                        displayResults(data.report);
                    } else {
                        showError(data.error);
                    }
                } catch (error) {
                    showError('An error occurred during analysis');
                } finally {
                    document.getElementById('loading').style.display = 'none';
                }
            }
            
            function displayResults(report) {
                const results = document.getElementById('results');
                const riskScore = document.getElementById('riskScore');
                const classification = document.getElementById('classification');
                const threatIndicators = document.getElementById('threatIndicators');
                const recommendation = document.getElementById('recommendation');
                const details = document.getElementById('details');
                
                // Set risk score
                riskScore.textContent = `Risk Score: ${report.risk_score}/100`;
                riskScore.className = `risk-score ${report.classification.toLowerCase()}`;
                
                // Set classification
                classification.textContent = `Classification: ${report.classification}`;
                
                // Set threat indicators
                if (report.threat_indicators && report.threat_indicators.length > 0) {
                    threatIndicators.innerHTML = '<h3>Detected Threat Indicators:</h3>' + 
                        report.threat_indicators.map(i => `<div class="indicator">⚠️ ${i}</div>`).join('');
                } else {
                    threatIndicators.innerHTML = '<div class="indicator">✅ No threat indicators detected</div>';
                }
                
                // Set recommendation
                recommendation.innerHTML = `<strong>Recommendation:</strong> ${report.recommendation}`;
                
                // Set detailed analysis
                let detailsHTML = '';
                
                // Header Analysis
                if (report.header_analysis) {
                    detailsHTML += '<div class="detail-card"><h3>📧 Header Analysis</h3><ul>';
                    detailsHTML += `<li>SPF: ${report.header_analysis.spf_status}</li>`;
                    detailsHTML += `<li>DKIM: ${report.header_analysis.dkim_status}</li>`;
                    detailsHTML += `<li>DMARC: ${report.header_analysis.dmarc_status}</li>`;
                    detailsHTML += `<li>Forged Domain: ${report.header_analysis.forged_domain_detected ? '⚠️ Yes' : '✅ No'}</li>`;
                    detailsHTML += '</ul></div>';
                }
                
                // Domain Analysis
                if (report.domain_analysis) {
                    detailsHTML += '<div class="detail-card"><h3>🌐 Domain Analysis</h3><ul>';
                    
                    if (report.domain_analysis.typosquatting_detected.length > 0) {
                        detailsHTML += '<li>⚠️ Typosquatting detected</li>';
                    }
                    if (report.domain_analysis.new_domains.length > 0) {
                        detailsHTML += '<li>⚠️ New suspicious domains</li>';
                    }
                    if (report.domain_analysis.suspicious_tlds.length > 0) {
                        detailsHTML += '<li>⚠️ Suspicious TLDs</li>';
                    }
                    if (report.domain_analysis.domain_mismatches.length > 0) {
                        detailsHTML += '<li>⚠️ Domain mismatches</li>';
                    }
                    if (report.domain_analysis.typosquatting_detected.length === 0 && 
                        report.domain_analysis.new_domains.length === 0 &&
                        report.domain_analysis.suspicious_tlds.length === 0) {
                        detailsHTML += '<li>✅ No domain issues detected</li>';
                    }
                    
                    detailsHTML += '</ul></div>';
                }
                
                // Link Analysis
                if (report.link_analysis) {
                    detailsHTML += '<div class="detail-card"><h3>🔗 Link Analysis</h3><ul>';
                    detailsHTML += `<li>Total Links: ${report.link_analysis.total_links}</li>`;
                    
                    if (report.link_analysis.suspicious_domains.length > 0) {
                        detailsHTML += `<li>⚠️ Suspicious Domains: ${report.link_analysis.suspicious_domains.length}</li>`;
                    }
                    if (report.link_analysis.url_shorteners.length > 0) {
                        detailsHTML += `<li>⚠️ URL Shorteners: ${report.link_analysis.url_shorteners.length}</li>`;
                    }
                    if (report.link_analysis.redirect_chains.length > 0) {
                        detailsHTML += `<li>⚠️ Redirect Chains: ${report.link_analysis.redirect_chains.length}</li>`;
                    }
                    if (report.link_analysis.total_links === 0) {
                        detailsHTML += '<li>✅ No links detected</li>';
                    }
                    
                    detailsHTML += '</ul></div>';
                }
                
                // Language Analysis
                if (report.language_analysis) {
                    detailsHTML += '<div class="detail-card"><h3>💬 Language Analysis</h3><ul>';
                    
                    if (report.language_analysis.urgency_detected.length > 0) {
                        detailsHTML += `<li>⚠️ Urgency tactics: ${report.language_analysis.urgency_detected.length}</li>`;
                    }
                    if (report.language_analysis.threat_language_detected.length > 0) {
                        detailsHTML += `<li>⚠️ Threat language: ${report.language_analysis.threat_language_detected.length}</li>`;
                    }
                    if (report.language_analysis.credential_harvesting.length > 0) {
                        detailsHTML += `<li>⚠️ Credential harvesting: ${report.language_analysis.credential_harvesting.length}</li>`;
                    }
                    if (report.language_analysis.urgency_detected.length === 0 && 
                        report.language_analysis.threat_language_detected.length === 0 &&
                        report.language_analysis.credential_harvesting.length === 0) {
                        detailsHTML += '<li>✅ No social engineering detected</li>';
                    }
                    
                    detailsHTML += '</ul></div>';
                }
                
                // Attachment Analysis
                if (report.attachment_analysis) {
                    detailsHTML += '<div class="detail-card"><h3>📎 Attachment Analysis</h3><ul>';
                    
                    if (report.attachment_analysis.has_attachments) {
                        detailsHTML += `<li>Total Attachments: ${report.attachment_analysis.attachments.length}</li>`;
                        
                        if (report.attachment_analysis.dangerous_attachments.length > 0) {
                            detailsHTML += `<li>⚠️ Dangerous attachments: ${report.attachment_analysis.dangerous_attachments.length}</li>`;
                            report.attachment_analysis.dangerous_attachments.forEach(att => {
                                detailsHTML += `<li><small>⚠️ ${att.filename}: ${att.reason}</small></li>`;
                            });
                        }
                    } else {
                        detailsHTML += '<li>✅ No attachments detected</li>';
                    }
                    
                    detailsHTML += '</ul></div>';
                }
                
                details.innerHTML = detailsHTML;
                results.style.display = 'block';
            }
            
            function showError(message) {
                const error = document.getElementById('error');
                error.textContent = `Error: ${message}`;
                error.style.display = 'block';
                document.getElementById('results').style.display = 'none';
            }
        </script>
    </body>
    </html>
    '''

@app.route('/analyze', methods=['POST'])
def analyze():
    """Analyze email headers and body"""
    try:
        data = request.get_json()
        headers_text = data.get('headers', '')
        body_text = data.get('body', '')
        
        # Parse email
        full_email = f"{headers_text}\n\n{body_text}"
        msg = BytesParser(policy=policy.default).parsebytes(full_email.encode())
        
        # Initialize analyzers
        header_analyzer = HeaderAnalyzer()
        domain_analyzer = DomainAnalyzer()
        language_analyzer = LanguageAnalyzer()
        link_analyzer = LinkAnalyzer()
        attachment_analyzer = AttachmentAnalyzer()
        risk_scorer = RiskScorer()
        
        # Perform analyses
        header_results = header_analyzer.analyze(headers_text, msg)
        domain_results = domain_analyzer.analyze(msg)
        language_results = language_analyzer.analyze(body_text)
        link_results = link_analyzer.analyze(body_text)
        attachment_results = attachment_analyzer.analyze(msg)
        
        # Calculate risk score
        all_indicators = {
            'header': header_results,
            'domain': domain_results,
            'language': language_results,
            'links': link_results,
            'attachments': attachment_results
        }
        
        risk_score, classification = risk_scorer.calculate_risk(all_indicators)
        
        # Generate final report
        report = {
            'risk_score': risk_score,
            'classification': classification,
            'header_analysis': header_results,
            'domain_analysis': domain_results,
            'language_analysis': language_results,
            'link_analysis': link_results,
            'attachment_analysis': attachment_results,
            'threat_indicators': risk_scorer.get_threat_indicators(),
            'recommendation': risk_scorer.get_recommendation(classification)
        }
        
        return jsonify({'success': True, 'report': report})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ==================== MAIN APPLICATION ====================
if __name__ == '__main__':
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║     AI-Powered Email Security Analyzer                   ║
    ║     Professional SOC-grade Email Threat Detection        ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Run the application
    app.run(debug=True, host='0.0.0.0', port=5000)
