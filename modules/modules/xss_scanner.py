from urllib.parse import urlparse, urljoin, urlencode, parse_qs
from typing import Dict, List, Optional, Tuple, Any

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<iframe src=javascript:alert('XSS')>",
]

class XSSScanner:
    def __init__(self, target: str):
        self.target = target
        self.vulnerabilities = []
        
    def scan_url(self, url: str) -> List[Dict]:
        results = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for param_name in params.keys():
            for payload in XSS_PAYLOADS:
                test_params = params.copy()
                test_params[param_name] = [payload]
                test_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                      parsed.params, test_query, parsed.fragment))
                
                try:
                    response = requests.get(test_url, timeout=10)
                    
                    # Verificar si el payload está reflejado sin encoding
                    if payload in response.text:
                        results.append({
                            'type': 'Reflected XSS',
                            'parameter': param_name,
                            'payload': payload,
                            'url': test_url,
                            'severity': 'MEDIUM'
                        })
                        print(f"[!] XSS encontrado en: {param_name}")
                except:
                    pass
        
        return results

def scan(target: str, urls: List[str] = None) -> Dict:
    scanner = XSSScanner(target)
    results = []
    
    if not urls:
        urls = [f"http://{target}"]
    
    for url in urls:
        results.extend(scanner.scan_url(url))
    
    print(f"\n[+] Total XSS vulnerabilities: {len(results)}")
    return {'target': target, 'vulnerabilities': results}
