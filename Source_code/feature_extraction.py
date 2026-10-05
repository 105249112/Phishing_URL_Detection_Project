import re                      
import ipaddress                   
import pandas as pd               
from types import SimpleNamespace  
from urllib.parse import urlsplit  



# the shape of a valid scheme for example   http, https, ftp
scheme = r"[a-zA-Z][a-zA-Z0-9+\-.]*"

# matches any existing schemes for example   http://, https://, ftp://
scheme_pattern = re.compile(rf"^{scheme}://")

# matches a second scheme stuck after the first for example we had in our dataset http://ftp://
double_scheme_pattern = re.compile(rf"^{scheme}://({scheme}://.*)$")

# cleans up the URL so it can be parsed correctly
def parse_url(url):
    cleaned = url.strip()

    # some URLs have two schemes stuck together for example in the dataset we had http://ftp://
    double_match = double_scheme_pattern.match(cleaned)
    if double_match:
        cleaned = double_match.group(1)

    # adds http:// only if the URL still has no scheme at all
    if not scheme_pattern.match(cleaned):
        cleaned = "http://" + cleaned
    try:
        return urlsplit(cleaned)
    except ValueError:
        return SimpleNamespace(netloc="", path="")  


# counts how many characters are in the URL
def url_length(url):
    return len(url) 

# counts how many hyphens are in the URL
def hyphen_count(url):
    return url.count("-")  

# counts how many numbers are in the URL
def number_count(url):
    return sum(c.isnumeric() for c in url)   

# checks if the URL uses https instead of http
def uses_https(url):
    return int(url.lower().startswith("https://"))  

# checks if the domain is a valid IP address instead of a name
def has_ip(url):
    host = parse_url(url).netloc.split(":")[0]
    try:
        ipaddress.ip_address(host)
        return 1
    except ValueError:
        return 0

# counts how many subdomain levels are before the main domain
def subdomain_count(url):
    if has_ip(url):
        return 0
    host = parse_url(url).netloc.split(":")[0]     
    parts = host.split(".")                       
    return len(parts) - 2 if len(parts) > 2 else 0  

# checks for '@', which hides the real link before it
def has_at_symbol(url):
    return int("@" in url)   

# checks for a '//' redirect trick after the protocol
def has_double_slash_redirect(url):
    protocol_end = url.find("://")          
    if protocol_end == -1:
        return int("//" in url)           
    rest = url[protocol_end + 3:]         
    return int("//" in rest)               

# counts how many folders deep the URL path goes
def path_depth(url):
    path = parse_url(url).path                        
    segments = [seg for seg in path.split("/") if seg] 
    return len(segments)                             

# numbers often used to fake letters they look similar to, e.g. g00gle, paypa1
lookalike_numbers = {"0", "1", "3", "4", "5", "7", "8", "9"}   

# checks if a domain swaps numbers in for letters to imitate a real brand name
def has_lookalike_chars(url):
    host = parse_url(url).netloc.split(":")[0]   
    for label in host.split("."):               
        letters = sum(c.isalpha() for c in label)         
        subs = sum(c in lookalike_numbers for c in label)  
        if letters >= 3 and subs >= 1:         
            return 1
    return 0 

# domain endings commonly used for phishing
high_risk_tlds = {
    "xin", "bond", "help","win","cfd","tk","ml","ga","cf","gq",                     
    "top", "xyz", "click", "link","icu", "rest", "zip", "mov",   
}

# checks if the domain ends in a TLD which is commonly used for phishing
def tld_risk(url):
    host = parse_url(url).netloc.split(":")[0].lower()   
    tld = host.split(".")[-1] if "." in host else ""            
    return int(tld in high_risk_tlds)                          

# words commonly used in phishing URLs to sound trustworthy or urgent
suspicious_keywords = {
    "login", "verify", "secure", "account", "update",
    "confirm", "signin", "banking", "password",
}

# checks for words phishing URLs commonly use to look legitimate or urgent
def has_suspicious_keyword(url):
    text = url.lower()
    return int(any(word in text for word in suspicious_keywords))

def extract_features(url):
    return {
        "url_length": url_length(url),
        "hyphen_count": hyphen_count(url),
        "number_count": number_count(url),
        "uses_https": uses_https(url),
        "has_ip": has_ip(url),
        "subdomain_count": subdomain_count(url),
        "has_at_symbol": has_at_symbol(url),
        "has_double_slash_redirect": has_double_slash_redirect(url),
        "path_depth": path_depth(url),
        "has_lookalike_chars": has_lookalike_chars(url),
        "tld_risk": tld_risk(url),
        "has_suspicious_keyword": has_suspicious_keyword(url)
    }

if __name__ == "__main__":

    # loads the cleaned dataset
    df = pd.read_csv("../Datasets/combined_cleaned.csv")

    print("Loaded shape:")
    print(df.shape)

    print("\nColumns:", df.columns.tolist())
    # add each feature as a new column
    df["url_length"] = df["url"].apply(url_length)                            
    df["hyphen_count"] = df["url"].apply(hyphen_count)                    
    df["number_count"] = df["url"].apply(number_count)                          
    df["uses_https"] = df["url"].apply(uses_https)                           
    df["has_ip"] = df["url"].apply(has_ip)                                    
    df["subdomain_count"] = df["url"].apply(subdomain_count)                 
    df["has_at_symbol"] = df["url"].apply(has_at_symbol)                       
    df["has_double_slash_redirect"] = df["url"].apply(has_double_slash_redirect)  
    df["path_depth"] = df["url"].apply(path_depth)                             
    df["has_lookalike_chars"] = df["url"].apply(has_lookalike_chars)          
    df["tld_risk"] = df["url"].apply(tld_risk)                              
    df["has_suspicious_keyword"] = df["url"].apply(has_suspicious_keyword)

    print("\nFinal shape:")  
    print(df.shape)         # shows the row and column count after features were added

    print("\nFirst 8 rows:")          
    preview = df.head(8).copy()       
    preview.index = range(1, 9)       # starts at 1 because i didnt want it to start at 0
    print(preview)                    

    df.to_csv("../Datasets/feature_dataset.csv", index=False)   

    print("\nFeature dataset saved successfully.")    
    print("File: ../Datasets/feature_dataset.csv")