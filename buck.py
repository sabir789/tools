#!/usr/bin/env python3
"""
Enhanced Cloud Bucket & Misconfiguration Scanner
Supports: company name, domain, or full URL input
Uses multi-threading for speed and content validation to reduce false positives.
"""

import requests
import sys
import re
import os
import argparse
import concurrent.futures
import threading
from urllib.parse import urlparse
import urllib3

# Disable SSL warnings for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Colors ---
GREEN  = '\033[0;32m'
YELLOW = '\033[1;33m'
RED    = '\033[0;31m'
CYAN   = '\033[0;36m'
NC     = '\033[0m'

# --- Config ---
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
TIMEOUT = 7
MAX_THREADS = 50

# --- Global Output Lock ---
print_lock = threading.Lock()
findings_lock = threading.Lock()
findings = []  # Collect all results

def safe_print(message):
    with print_lock:
        print(message)

def add_finding(severity, check_type, url, status, detail=""):
    with findings_lock:
        findings.append({
            "severity": severity,
            "check_type": check_type,
            "url": url,
            "status": status,
            "detail": detail
        })

# --- False Positive Detection ---
# Common strings found on error/login/404 pages that indicate a soft-404 or redirect to auth
FALSE_POSITIVE_SIGNATURES = [
    "page not found", "404 not found", "not found",
    "access denied", "unauthorized", "forbidden",
    "sign in", "log in", "login", "please login",
    "authentication required", "you must be logged in",
    "the page you requested", "does not exist",
    "error occurred", "something went wrong",
    "default web site page", "welcome to nginx",
    "it works!", "apache2 ubuntu default page",
    "test page for", "under construction",
    "index of /",  # Directory listing (separate handling)
    "the resource you are looking for has been removed",
    "this page isn't working",
]

# Specific content signatures that CONFIRM a real finding (not false positive)
CONFIRM_SIGNATURES = {
    # --- Cloud Storage ---
    "Bucket": ["<ListBucketResult", "<ListAllMyBucketsResult", "<Error><Code>AccessDenied",
               "NoSuchBucket", "AllAccessDisabled", "<Contents>"],
    # --- Source Code Leaks ---
    "Git Repository": ["ref: refs/heads/"],
    "Git Config": ["[core]", "[remote", "repositoryformatversion"],
    "Git Log": ["commit ", "Author:", "Date:"],
    "SVN Entries": ["svn", "dir\n"],
    "DS_Store": ["\x00\x00\x00\x01Bud1"],
    "Source Map": ['"version":', '"sources":', '"mappings":'],
    # --- Secrets & Config ---
    "Environment File": ["DB_PASSWORD", "DB_HOST", "APP_KEY", "SECRET_KEY", "API_KEY",
                         "AWS_ACCESS_KEY", "STRIPE_SECRET", "PRIVATE_KEY", "DATABASE_URL"],
    "Docker Compose": ["services:", "image:", "container_name:"],
    "Dockerfile": ["FROM ", "RUN ", "COPY ", "EXPOSE "],
    "SFTP Config": ['"host":', '"username":', '"password":'],
    "VSCode SFTP Config": ['"host":', '"username":'],
    "SSH Private Key": ["-----BEGIN", "PRIVATE KEY"],
    "AWS Credentials": ["aws_access_key_id", "aws_secret_access_key"],
    "Htpasswd": ["$apr1$", "{SHA}", "$2y$"],
    # --- Spring Boot ---
    "Spring Boot Actuator": ['"status":', '"beans":', '"contextId":'],
    "Spring Boot Heapdump": [],  # Binary file
    "Spring Boot Env": ['"propertySources":', '"activeProfiles":'],
    "Spring Boot Gateway Routes": ['"route_id":', '"predicates":'],
    "Spring Boot Metrics": ['"names":', '"jvm.memory'],
    "Spring Boot Mappings": ['"dispatcherServlets":', '"handler":'],
    "Spring Boot Beans": ['"beans":', '"scope":'],
    "Spring Boot Configprops": ['"contexts":', '"beans":'],
    "Spring Boot Loggers": ['"loggers":', '"effectiveLevel":'],
    # --- API Docs ---
    "Swagger Docs": ['"swagger":', '"openapi":', '"paths":'],
    "Swagger UI": ["swagger-ui", "SwaggerUIBundle"],
    "GraphQL Introspection": ['"__schema"', '"types"'],
    "GraphQL Playground": ["GraphQL Playground", "graphql-playground"],
    # --- Databases ---
    "Elasticsearch": ['"cluster_name":', '"tagline" : "You Know, for Search"'],
    "Elasticsearch Indices": ["health", "status", "index", "docs.count"],
    "Kibana": ["kibana", "Elastic"],
    "CouchDB": ['"couchdb":', '"version":'],
    "MongoDB Express": ["mongo-express", "Mongo Express"],
    "Redis Commander": ["redis-commander", "Redis Commander"],
    "Adminer": ["adminer", "Adminer"],
    "phpMyAdmin": ["phpmyadmin", "phpMyAdmin"],
    # --- Infrastructure ---
    "Prometheus": ["# HELP", "# TYPE", "process_"],
    "Grafana": ["grafana", "Grafana"],
    "Portainer": ["portainer", "Portainer"],
    "Traefik": ['"entryPoints":', '"routers":', '"traefik"'],
    "ArgoCD": ["argocd", "Argo CD"],
    "Rancher": ["rancher", "Rancher"],
    "Kubernetes Dashboard": ["kubernetes-dashboard", "Kubernetes Dashboard"],
    "Kubernetes API": ['"kind":', '"apiVersion":'],
    "MinIO Console": ["minio", "MinIO"],
    "MinIO API": ['"buckets":', 'ListBuckets'],
    "Apache Status": ["Apache Server Status", "Total Accesses"],
    "Nginx Status": ["Active connections:", "server accepts"],
    "Docker Registry": ['"repositories":'],
    "Consul Agent": ['"Config":', '"Member":'],
    "Vault Health": ['"initialized":', '"sealed":'],
    # --- AI/ML ---
    "ChromaDB": ['"heartbeat"', '"nanosecond heartbeat"'],
    "Qdrant": ['"collections"'],
    "Milvus": ['"collection_names"'],
    "Weaviate": ['"hostname":', '"modules":'],
    "MLflow": ['"experiments"'],
    "Airflow Admin": ["airflow", "DAGs"],
    "Airflow DAGs API": ['"dags":', '"dag_id":'],
    "TensorBoard": ['"logdir"'],
    "Jupyter": ["jupyter", "Jupyter"],
    "OpenAI Config": ["sk-", "api_key", "openai"],
    # --- CMS / Frameworks ---
    "Laravel Telescope": ["telescope", "Telescope"],
    "Laravel Debug": ['"message":', '"exception":', '"file":'],
    "Magento Config Leak": ["<config", "<connection>", "<host>"],
    "WordPress Users": ['"id":', '"slug":', '"name":'],
    "WordPress Debug": ["PHP Fatal error", "PHP Warning", "Stack trace"],
    "Drupal": ["Drupal", "drupal"],
    "Strapi Admin": ['"data":', '"strapiVersion":'],
    "Directus": ['"directus":', '"project":'],
    # --- Node.js / PHP ---
    "Node.js Package": ['"name":', '"version":', '"dependencies":'],
    "Node.js Package Lock": ['"lockfileVersion":', '"dependencies":'],
    "PHP Composer": ['"require":', '"autoload":'],
    "Pytest Cache": ["lastfailed"],
    # --- AEM ---
    "AEM QueryBuilder": ['"results":', '"hits":'],
    "AEM CRX": ["CRXDE", "crx/de"],
    # --- SaaS/IdP ---
    "Firebase DB": [],
    "Okta Tenant": ['"issuer":', '"authorization_endpoint":'],
    "Auth0 Tenant": ['"issuer":', '"authorization_endpoint":'],
    "Keycloak Realm": ['"realm":', '"public_key":'],
    "ServiceNow KB": ["knowledge", "article"],
    # --- Logs & Debug ---
    "Log File": ["[error]", "[warning]", "Exception", "Traceback", "Stack trace"],
    "Laravel Log": ["[stacktrace]", "production.ERROR", "local.ERROR"],
    "Sentry DSN": ["sentry.io", "@sentry", "dsn="],
    # --- CI/CD ---
    "Jenkins Script Console": ["Groovy script", "Jenkins"],
    "Jenkins User Enum": ['"user":', '"fullName":'],
    "GitLab Explore": ["GitLab", "projects"],
    "GitLab Snippets": ["snippet", "GitLab"],
    # --- Backup ---
    "Backup File": [],  # Binary / varies - check content-type instead
    "Backup Archive": [],  # Binary
    "Database Dump": ["INSERT INTO", "CREATE TABLE", "mysqldump", "pg_dump"],
}


def is_false_positive(response_text, check_type, content_type=""):
    """
    Determines if a 200 response is a false positive by analyzing content.
    Returns True if it's likely a false positive (login page, error page, etc.)
    """
    if not response_text:
        return True  # Empty response is not a real finding

    text_lower = response_text[:5000].lower()  # Only check first 5KB
    
    # If we have specific confirmation signatures for this check type, use them
    if check_type in CONFIRM_SIGNATURES and CONFIRM_SIGNATURES[check_type]:
        for sig in CONFIRM_SIGNATURES[check_type]:
            if sig.lower() in text_lower:
                return False  # Confirmed real finding
        # If none of the confirmation signatures matched, it's likely false positive
        return True
    
    # For check types without specific signatures, use generic false positive detection
    # Count how many false positive signatures match
    fp_score = 0
    for sig in FALSE_POSITIVE_SIGNATURES:
        if sig in text_lower:
            fp_score += 1
    
    # If multiple false positive signatures found, it's likely a soft-404 or error page
    if fp_score >= 2:
        return True
    
    # Check if response is HTML when we expect data (JSON, YAML, etc.)
    if content_type and "text/html" in content_type:
        # Most API/config endpoints should NOT return HTML
        data_check_types = [
            "Spring Boot", "Swagger", "GraphQL", "Metrics", "Prometheus",
            "ChromaDB", "Qdrant", "Milvus", "Weaviate", "MLflow",
            "Prefect", "TensorBoard", "Docker Registry", "Consul", "Vault",
            "Kubernetes", "Node.js Package", "PHP Composer", "Pytest",
        ]
        for dct in data_check_types:
            if dct in check_type:
                return True  # HTML response for a data endpoint = false positive
    
    return False


def check_url(url, check_type="Generic"):
    """
    Enhanced URL checker with false positive reduction.
    Uses allow_redirects=False to detect actual redirects properly.
    """
    try:
        # First request: DON'T follow redirects to see the real status
        response = requests.get(
            url,
            headers={"User-Agent": USER_AGENT},
            timeout=TIMEOUT,
            allow_redirects=False,
            verify=False
        )
        status = response.status_code

        # Handle redirects explicitly
        if status in [301, 302, 303, 307, 308]:
            location = response.headers.get("Location", "unknown")
            # Check if redirect goes to a login page (common false positive)
            if any(kw in location.lower() for kw in ["login", "signin", "auth", "sso", "account"]):
                # Redirect to login = not a real finding, just skip silently
                return False, url, status
            else:
                safe_print(f"{YELLOW}[>] {check_type} REDIRECT ({status}) -> {url} => {location}{NC}")
                return False, url, status

        elif status == 200:
            content_type = response.headers.get("Content-Type", "")
            body = response.text

            # Special bucket handling - check for actual bucket XML responses
            if "Bucket" in check_type:
                if "<ListBucketResult" in body or "<ListAllMyBucketsResult" in body:
                    safe_print(f"{RED}[!!!] OPEN BUCKET (200) -> {url}{NC}")
                    add_finding("CRITICAL", check_type, url, status, "Open bucket with listing")
                    return True, url, status
                elif "<Error>" in body:
                    # Bucket exists but has an error (AccessDenied, etc.)
                    if "AccessDenied" in body:
                        safe_print(f"{YELLOW}[*] Bucket EXISTS but Private -> {url}{NC}")
                        return True, url, status
                    elif "NoSuchBucket" in body:
                        return False, url, status  # Bucket doesn't exist
                    return False, url, status
                elif "BlobNotFound" in body or "ResourceNotFound" in body:
                    return False, url, status  # Azure blob doesn't exist
                elif not body.strip():
                    return False, url, status  # Empty = likely doesn't exist
                else:
                    # Generic 200 for bucket - could be anything, validate content
                    if is_false_positive(body, check_type, content_type):
                        return False, url, status
                    safe_print(f"{RED}[!!!] {check_type} FOUND (200) -> {url}{NC}")
                    add_finding("HIGH", check_type, url, status)
                    return True, url, status
            else:
                # Non-bucket checks: validate content to reduce false positives
                if is_false_positive(body, check_type, content_type):
                    return False, url, status  # Skip silently - it's a false positive
                
                safe_print(f"{RED}[!!!] {check_type} FOUND (200) -> {url}{NC}")
                add_finding("HIGH", check_type, url, status)
                return True, url, status

        elif status == 403:
            if "Bucket" in check_type:
                safe_print(f"{YELLOW}[*] {check_type} EXISTS but Private (403) -> {url}{NC}")
            # For non-bucket, 403 is mostly noise - skip silently
            return False, url, status

        elif status == 401:
            # 401 means the endpoint exists but needs auth
            safe_print(f"{YELLOW}[*] {check_type} AUTH REQUIRED (401) -> {url}{NC}")
            return False, url, status

        return False, url, status

    except requests.exceptions.ConnectionError:
        return False, url, 0
    except requests.exceptions.Timeout:
        return False, url, 0
    except requests.exceptions.RequestException:
        return False, url, 0


# --- Check Functions ---

def scan_cloud_buckets(target_permutations):
    safe_print(f"\n{GREEN}{'='*50}{NC}")
    safe_print(f"{GREEN} Cloud Bucket Enumeration (Threads: {MAX_THREADS}){NC}")
    safe_print(f"{GREEN} Scanning {len(target_permutations)} permutation(s){NC}")
    safe_print(f"{GREEN}{'='*50}{NC}")

    urls_to_scan = []

    # Provider Templates
    templates = [
        # AWS
        "https://{}.s3.amazonaws.com",
        "https://s3.amazonaws.com/{}",
        "https://{}.s3.us-east-1.amazonaws.com",
        "https://{}.s3.us-west-1.amazonaws.com",
        "https://{}.s3.us-west-2.amazonaws.com",
        # GCS
        "https://storage.googleapis.com/{}",
        "https://{}.storage.googleapis.com",
        "https://firebasestorage.googleapis.com/v0/b/{}/o",
        # Azure
        "https://{}.blob.core.windows.net",
        "https://{}.blob.core.windows.net/?comp=list",
        "https://{}.blob.core.windows.net/public",
        # Wasabi
        "https://{}.s3.wasabisys.com",
    ]

    # Regions
    do_regions = ["nyc1", "nyc2", "nyc3", "ams2", "ams3", "sgp1", "lon1", "fra1", "tor1", "blr1", "sfo1", "sfo2", "sfo3"]
    linode_regions = ["us-east-1", "us-southeast-1", "us-central-1", "us-west-1", "eu-central-1", "eu-west-1", "ap-south-1"]
    alibaba_regions = ["cn-hangzhou", "cn-shanghai", "cn-qingdao", "cn-beijing", "cn-zhangjiakou", "cn-huhehaote", "cn-shenzhen", "cn-heyuan", "cn-guangzhou", "cn-chengdu", "cn-hongkong", "ap-southeast-1", "ap-southeast-2", "ap-southeast-3", "ap-southeast-5", "ap-northeast-1", "ap-south-1", "eu-central-1", "eu-west-1", "us-west-1", "us-east-1", "me-east-1"]
    tencent_regions = ["ap-beijing", "ap-guangzhou", "ap-shanghai", "ap-chengdu", "ap-chongqing", "ap-singapore", "ap-hongkong", "na-toronto", "na-siliconvalley", "eu-frankfurt"]
    backblaze_regions = ["us-west-000", "us-west-001", "us-west-002", "us-east-003", "us-east-004", "eu-central-003"]

    for region in do_regions:
        templates.append(f"https://{{}}.{region}.digitaloceanspaces.com")
    for region in linode_regions:
        templates.append(f"https://{{}}.{region}.linodeobjects.com")
    for region in alibaba_regions:
        templates.append(f"https://{{}}.oss-{region}.aliyuncs.com")
        templates.append(f"https://{{}}.{region}.aliyuncs.com")
    for region in tencent_regions:
        templates.append(f"https://{{}}.cos.{region}.myqcloud.com")
    for region in backblaze_regions:
        templates.append(f"https://{{}}.s3.{region}.backblazeb2.com")

    # DreamHost & IBM
    templates.append("https://objects-us-east-1.dream.io/{}")
    templates.append("https://{}.s3.us.cloud-object-storage.appdomain.cloud")
    templates.append("https://{}.s3.eu.cloud-object-storage.appdomain.cloud")

    for perm in target_permutations:
        for temp in templates:
            urls_to_scan.append(temp.format(perm))

    safe_print(f"{CYAN}[*] Total bucket URLs to scan: {len(urls_to_scan)}{NC}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(check_url, url, "Bucket"): url for url in urls_to_scan}
        for future in concurrent.futures.as_completed(futures):
            pass


def check_firebase_db(name):
    """Check for open Firebase Realtime Databases with content validation."""
    url = f"https://{name}.firebaseio.com/.json"
    try:
        r = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT, verify=False)
        if r.status_code == 200:
            body = r.text.strip()
            # Firebase returns "null" for databases that exist but are empty
            if body and body != "null":
                safe_print(f"{RED}[!!!] CRITICAL: OPEN FIREBASE DB -> {url}{NC}")
                add_finding("CRITICAL", "Firebase DB", url, 200, f"Data exposed: {body[:100]}...")
            elif body == "null":
                safe_print(f"{YELLOW}[*] Firebase DB exists but empty -> {url}{NC}")
        elif r.status_code == 401:
            # Exists but secured - this is expected behavior, not worth printing
            pass
    except:
        pass


def check_jira(base_url, company):
    safe_print(f"\n{GREEN}--- Jira Misconfiguration Scan ---{NC}")
    jira_urls = [
        f"https://{company}.atlassian.net",
        f"https://jira.{company}.com",
        f"{base_url}/jira"
    ]

    endpoints = [
        ("/secure/Dashboard.jspa", "Jira Dashboard"),
        ("/secure/ManageFilters.jspa", "Jira Filters"),
        ("/secure/ViewUserHover.jspa", "Jira User Enum"),
        ("/secure/ContactAdministrators!default.jspa", "Jira Admin Contact"),
        ("/servicedesk/customer/user/signup", "Jira Service Desk Signup"),
        ("/rest/api/2/user/picker?query=admin", "Jira User Picker API"),
        ("/secure/ConfigurePortalPages!default.jspa", "Jira Portal Config"),
    ]

    for j_url in jira_urls:
        try:
            r = requests.get(j_url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT, allow_redirects=False, verify=False)
            if r.status_code in [200, 302, 301]:
                safe_print(f"{GREEN}[+] JIRA INSTANCE FOUND -> {j_url} ({r.status_code}){NC}")
                with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                    futures = {executor.submit(check_url, f"{j_url}{ep}", name): ep for ep, name in endpoints}
                    concurrent.futures.wait(futures)
        except:
            pass


def check_app_vulns(base_url):
    safe_print(f"\n{GREEN}--- App Vulnerability Scan ---{NC}")

    check_list = [
        # Spring Boot Actuator (PROVEN HIGH BOUNTY)
        ("/actuator", "Spring Boot Actuator"),
        ("/actuator/env", "Spring Boot Env"),
        ("/actuator/heapdump", "Spring Boot Heapdump"),
        ("/actuator/configprops", "Spring Boot Configprops"),
        ("/actuator/mappings", "Spring Boot Mappings"),
        ("/actuator/gateway/routes", "Spring Boot Gateway Routes"),
        ("/env", "Spring Boot Env"),
        ("/heapdump", "Spring Boot Heapdump"),
        # Source Code Exposure (PROVEN HIGH BOUNTY)
        ("/.git/HEAD", "Git Repository"),
        ("/.git/config", "Git Config"),
        # Secrets (PROVEN CRITICAL BOUNTY)
        ("/.env", "Environment File"),
        ("/.env.local", "Environment File"),
        ("/.env.bak", "Environment File"),
        ("/.vscode/sftp.json", "VSCode SFTP Config"),
        ("/sftp-config.json", "SFTP Config"),
        ("/wp-config.php.bak", "Environment File"),
        ("/docker-compose.yml", "Docker Compose"),
        # Swagger/OpenAPI (PROVEN MEDIUM BOUNTY)
        ("/v2/api-docs", "Swagger Docs"),
        ("/swagger.json", "Swagger Docs"),
        ("/swagger-ui.html", "Swagger UI"),
        ("/swagger-ui/", "Swagger UI"),
        ("/api-docs", "Swagger Docs"),
        # Debug (PROVEN HIGH BOUNTY)
        ("/_debugbar/open", "Laravel Debug"),
        ("/telescope/requests", "Laravel Telescope"),
        # Source Maps (PROVEN INFO DISCLOSURE)
        ("/main.js.map", "Source Map"),
        ("/app.js.map", "Source Map"),
    ]

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(check_url, f"{base_url}{path}", name): path for path, name in check_list}
        concurrent.futures.wait(futures)


def check_unique_vulns(base_url):
    safe_print(f"\n{GREEN}--- High-Value Vulnerability Checks ---{NC}")

    check_list = [
        # GraphQL (PROVEN HIGH BOUNTY)
        ("/graphql?query={__schema{types{name}}}", "GraphQL Introspection"),
        ("/graphql", "GraphQL Introspection"),
        ("/api/graphql", "GraphQL Introspection"),
        ("/graphiql", "GraphQL Playground"),
        # Jenkins (PROVEN HIGH BOUNTY - RCE)
        ("/jenkins/script", "Jenkins Script Console"),
        ("/script", "Jenkins Script Console"),
        # Exposed Metrics (PROVEN MEDIUM BOUNTY)
        ("/metrics", "Prometheus"),
        ("/grafana", "Grafana"),
    ]

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(check_url, f"{base_url}{path}", name): path for path, name in check_list}
        concurrent.futures.wait(futures)


def check_third_party(company, permutations):
    """Third-party checks with permutation support for subdomain-based services."""
    safe_print(f"\n{GREEN}--- Third-Party Integrations (Permutated) ---{NC}")

    urls = []
    # Path-based (use company only)
    urls.append((f"https://trello.com/b/{company}", "Trello Board"))
    urls.append((f"https://trello.com/{company}", "Trello Profile"))
    urls.append((f"https://www.postman.com/{company}", "Postman Workspace"))
    urls.append((f"https://circleci.com/gh/{company}", "CircleCI"))
    urls.append((f"https://travis-ci.org/{company}", "Travis CI (org)"))
    urls.append((f"https://travis-ci.com/{company}", "Travis CI (com)"))
    urls.append((f"https://dev.azure.com/{company}", "Azure DevOps Org"))

    # Subdomain-based (use permutations for broader coverage)
    for perm in permutations:
        urls.append((f"https://{perm}.zendesk.com", "Zendesk"))
        urls.append((f"https://{perm}.notion.site", "Notion Site"))
        urls.append((f"https://{perm}.slack.com", "Slack Workspace"))
        urls.append((f"https://{perm}.atlassian.net", "Atlassian Cloud"))
        urls.append((f"https://{perm}.atlassian.net/wiki", "Confluence"))
        urls.append((f"https://sonar.{perm}.com", "SonarQube"))
        urls.append((f"https://sonarqube.{perm}.com", "SonarQube Alt"))

    safe_print(f"{CYAN}[*] Testing {len(urls)} third-party URLs{NC}")
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(check_url, url, name): url for url, name in urls}
        concurrent.futures.wait(futures)


def check_overlooked(base_url, domain):
    safe_print(f"\n{GREEN}--- Overlooked Assets & Backups ---{NC}")

    paths = [
        # Backup archives (PROVEN CRITICAL BOUNTY)
        ("/backup.zip", "Backup Archive"), ("/backup.tar.gz", "Backup Archive"),
        ("/site.zip", "Backup Archive"), ("/www.zip", "Backup Archive"),
        ("/public.zip", "Backup Archive"),
        # Config backups
        ("/.env.bak", "Backup File"), ("/.env.old", "Backup File"),
        ("/config.php.bak", "Backup File"), ("/web.config.bak", "Backup File"),
        # Database dumps (PROVEN CRITICAL BOUNTY)
        ("/dump.sql", "Database Dump"), ("/database.sql", "Database Dump"),
        ("/db.sql", "Database Dump"), ("/backup.sql", "Database Dump"),
        # Laravel Log (PROVEN BOUNTY)
        ("/storage/logs/laravel.log", "Laravel Log"),
    ]

    check_list = [(f"{base_url}{p}", name) for p, name in paths]

    # Docker Registry (PROVEN CRITICAL)
    check_list.append((f"{base_url}/v2/_catalog", "Docker Registry"))
    check_list.append((f"https://registry.{domain}/v2/_catalog", "Docker Registry"))

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(check_url, url, name): url for url, name in check_list}
        concurrent.futures.wait(futures)


def check_ai_ml(base_url):
    """Only Jupyter — the one AI/ML check that actually produces bounties (RCE)."""
    safe_print(f"\n{GREEN}--- Jupyter Notebook Check (RCE) ---{NC}")

    check_list = [
        ("/notebooks", "Jupyter"),
        ("/tree", "Jupyter"),
        ("/lab", "Jupyter"),
        ("/api/kernels", "Jupyter"),
        ("/api/contents", "Jupyter"),
    ]

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_url, f"{base_url}{path}", name): path for path, name in check_list}
        concurrent.futures.wait(futures)


def check_databases(base_url, domain):
    """Exposed DB panels — subdomain + port-based."""
    safe_print(f"\n{GREEN}--- Exposed Database Panels ---{NC}")

    check_list = [
        # Elasticsearch (CRITICAL — full data read/write)
        (f"{base_url}:9200/", "Elasticsearch"),
        (f"{base_url}:9200/_cat/indices?v", "Elasticsearch Indices"),
        (f"https://es.{domain}", "Elasticsearch"),
        (f"https://elasticsearch.{domain}", "Elasticsearch"),
        (f"https://elastic.{domain}", "Elasticsearch"),
        # Kibana (HIGH — ES query interface)
        (f"{base_url}:5601/", "Kibana"),
        (f"{base_url}:5601/app/kibana", "Kibana"),
        (f"https://kibana.{domain}", "Kibana"),
        (f"{base_url}/kibana", "Kibana"),
        # CouchDB (CRITICAL — full data access)
        (f"{base_url}:5984/", "CouchDB"),
        (f"{base_url}:5984/_all_dbs", "CouchDB"),
        # MongoDB (CRITICAL — data dump)
        (f"{base_url}:27017/", "MongoDB"),
        # Redis Commander (CRITICAL — key dump)
        (f"{base_url}:8081/", "Redis Commander"),
        (f"https://redis.{domain}", "Redis Commander"),
        # Mongo Express (CRITICAL — full DB GUI)
        (f"{base_url}:8081/", "MongoDB Express"),
        (f"https://mongo.{domain}", "MongoDB Express"),
        # phpMyAdmin / Adminer via path (CRITICAL)
        (f"{base_url}/phpmyadmin/", "phpMyAdmin"),
        (f"{base_url}/pma/", "phpMyAdmin"),
        (f"{base_url}/adminer.php", "Adminer"),
    ]

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(check_url, url, name): url for url, name in check_list}
        concurrent.futures.wait(futures)


def check_infra_dashboards(base_url, domain):
    """Infrastructure dashboards — subdomain + port-based."""
    safe_print(f"\n{GREEN}--- Infrastructure Dashboards & Port Scan ---{NC}")

    check_list = [
        # Portainer (CRITICAL — Docker container mgmt)
        (f"{base_url}:9000/", "Portainer"),
        (f"{base_url}:9443/", "Portainer"),
        (f"https://portainer.{domain}", "Portainer"),
        (f"{base_url}/portainer/", "Portainer"),
        # Jenkins (CRITICAL — RCE via script console)
        (f"{base_url}:8080/", "Jenkins"),
        (f"{base_url}:8080/script", "Jenkins Script Console"),
        (f"{base_url}:8080/manage", "Jenkins Manage"),
        (f"https://jenkins.{domain}", "Jenkins"),
        # Grafana (HIGH — dashboards + data sources leak)
        (f"{base_url}:3000/", "Grafana"),
        (f"{base_url}:3000/login", "Grafana"),
        (f"{base_url}:3000/api/datasources", "Grafana Datasources"),
        (f"https://grafana.{domain}", "Grafana"),
        # RabbitMQ Management (HIGH — queue data)
        (f"{base_url}:15672/", "RabbitMQ"),
        (f"https://rabbitmq.{domain}", "RabbitMQ"),
        # Prometheus (HIGH — internal metrics/secrets)
        (f"{base_url}:9090/", "Prometheus"),
        (f"{base_url}:9090/graph", "Prometheus"),
        (f"{base_url}:9090/api/v1/targets", "Prometheus Targets"),
        (f"https://prometheus.{domain}", "Prometheus"),
        # Kubernetes Dashboard (CRITICAL)
        (f"{base_url}:8443/", "Kubernetes Dashboard"),
        (f"{base_url}:10250/pods", "Kubelet API"),
        (f"https://dashboard.{domain}", "Kubernetes Dashboard"),
        # Docker API (CRITICAL — full container RCE)
        (f"{base_url}:2375/containers/json", "Docker API (Unauth)"),
        (f"{base_url}:2376/containers/json", "Docker API (TLS)"),
        (f"{base_url}:2375/images/json", "Docker API Images"),
        # etcd (CRITICAL — K8s secrets store)
        (f"{base_url}:2379/version", "etcd"),
        (f"{base_url}:2379/v2/keys/", "etcd Keys"),
        # Consul (HIGH — service discovery + KV store)
        (f"{base_url}:8500/", "Consul UI"),
        (f"{base_url}:8500/v1/agent/self", "Consul Agent"),
        (f"{base_url}:8500/v1/kv/?recurse", "Consul KV Store"),
        (f"https://consul.{domain}", "Consul"),
        # Vault (CRITICAL — secrets manager)
        (f"{base_url}:8200/", "HashiCorp Vault"),
        (f"{base_url}:8200/v1/sys/health", "Vault Health"),
        (f"{base_url}:8200/v1/sys/seal-status", "Vault Seal Status"),
        (f"https://vault.{domain}", "HashiCorp Vault"),
        # Solr (HIGH — search data exposure)
        (f"{base_url}:8983/solr/", "Apache Solr"),
        (f"{base_url}:8983/solr/admin/cores", "Solr Cores"),
        (f"https://solr.{domain}", "Apache Solr"),
        # MinIO Console (CRITICAL — object storage)
        (f"{base_url}:9001/", "MinIO Console"),
        (f"https://minio.{domain}", "MinIO Console"),
        (f"https://s3.{domain}", "MinIO/S3"),
        # Flower / Celery (HIGH — task queue monitoring)
        (f"{base_url}:5555/", "Celery Flower"),
        (f"https://flower.{domain}", "Celery Flower"),
        # Airflow (HIGH — DAG execution / RCE)
        (f"{base_url}:8080/admin/", "Airflow Admin"),
        (f"{base_url}:8080/api/v1/dags", "Airflow DAGs API"),
        (f"https://airflow.{domain}", "Airflow"),
        # Neo4j (HIGH — graph DB browser)
        (f"{base_url}:7474/", "Neo4j Browser"),
        (f"{base_url}:7687/", "Neo4j Bolt"),
        # ClickHouse (HIGH — analytics DB)
        (f"{base_url}:8123/", "ClickHouse HTTP"),
        (f"{base_url}:8123/?query=SHOW+DATABASES", "ClickHouse Databases"),
        # Traefik Dashboard (HIGH — reverse proxy config)
        (f"{base_url}:8080/dashboard/", "Traefik Dashboard"),
        (f"{base_url}:8080/api/rawdata", "Traefik API"),
        (f"https://traefik.{domain}", "Traefik"),
        # ArgoCD (HIGH — GitOps deployment secrets)
        (f"https://argocd.{domain}", "ArgoCD"),
        (f"https://argo.{domain}", "ArgoCD"),
        # Nomad (HIGH — HashiCorp job scheduler)
        (f"{base_url}:4646/", "Nomad UI"),
        (f"{base_url}:4646/v1/jobs", "Nomad Jobs API"),
        # Zookeeper (HIGH — distributed config)
        (f"{base_url}:2181/", "Zookeeper"),
        # SonarQube (HIGH — code quality / secrets in reports)
        (f"{base_url}:9000/projects", "SonarQube"),
        (f"https://sonarqube.{domain}", "SonarQube"),
        (f"https://sonar.{domain}", "SonarQube"),
        # Jupyter on common ports (CRITICAL — RCE)
        (f"{base_url}:8888/", "Jupyter Notebook"),
        (f"{base_url}:8888/tree", "Jupyter Notebook"),
        (f"{base_url}:8889/", "Jupyter Notebook"),
        # GitLab (HIGH — source code access)
        (f"{base_url}:8929/", "GitLab"),
        (f"https://gitlab.{domain}", "GitLab"),
        # PgAdmin (CRITICAL — PostgreSQL management)
        (f"{base_url}:5050/", "PgAdmin"),
        (f"{base_url}:5050/login", "PgAdmin"),
        # Kafka UI (HIGH — message queue data)
        (f"{base_url}:9021/", "Kafka Control Center"),
        (f"{base_url}:8080/", "Kafka UI"),
        # Zipkin / Jaeger (MEDIUM — tracing data)
        (f"{base_url}:9411/", "Zipkin"),
        (f"{base_url}:16686/", "Jaeger UI"),
        (f"https://jaeger.{domain}", "Jaeger"),
        # Flink (HIGH — job execution / data processing)
        (f"{base_url}:8081/", "Apache Flink"),
        (f"{base_url}:8081/#/overview", "Apache Flink Dashboard"),
        # Spark (HIGH — job data / RCE via submit)
        (f"{base_url}:4040/", "Spark UI"),
        (f"{base_url}:8080/json/", "Spark Master"),
        (f"{base_url}:18080/", "Spark History"),
        # Couchbase (CRITICAL — full data access)
        (f"{base_url}:8091/", "Couchbase Console"),
        (f"{base_url}:8091/pools/default/buckets", "Couchbase Buckets"),
        # Redis direct (CRITICAL — if HTTP probe gets banner)
        (f"{base_url}:6379/", "Redis"),
        # Memcached (HIGH — cache data dump)
        (f"{base_url}:11211/", "Memcached"),
        # NATS Monitoring (HIGH — messaging infra)
        (f"{base_url}:8222/", "NATS Monitoring"),
        (f"{base_url}:8222/connz", "NATS Connections"),
        # Hazelcast (HIGH — in-memory data grid)
        (f"{base_url}:5701/hazelcast/rest/cluster", "Hazelcast"),
        # Verdaccio / npm registry (HIGH — private packages)
        (f"{base_url}:4873/", "Verdaccio npm Registry"),
        (f"https://npm.{domain}", "npm Registry"),
        # Harbor Container Registry (CRITICAL — images)
        (f"{base_url}:4443/", "Harbor Registry"),
        (f"https://harbor.{domain}", "Harbor Registry"),
        (f"https://registry.{domain}", "Container Registry"),
        # Gitea (HIGH — source code)
        (f"{base_url}:3000/explore/repos", "Gitea"),
        (f"https://gitea.{domain}", "Gitea"),
        # Drone CI (HIGH — pipeline secrets)
        (f"https://drone.{domain}", "Drone CI"),
        (f"https://ci.{domain}", "CI Server"),
        # Argo Workflows (HIGH — job execution)
        (f"{base_url}:2746/", "Argo Workflows"),
        (f"https://argo-workflows.{domain}", "Argo Workflows"),
        # OpenSearch (CRITICAL — Elasticsearch fork)
        (f"{base_url}:9200/", "OpenSearch"),
        (f"{base_url}:5601/", "OpenSearch Dashboards"),
        # Weave Scope (CRITICAL — container topology + exec)
        (f"{base_url}:4040/", "Weave Scope"),
        (f"https://scope.{domain}", "Weave Scope"),
        # Cockpit (HIGH — Linux server management)
        (f"{base_url}:9090/", "Cockpit"),
        # Mattermost (HIGH — team chat data)
        (f"https://chat.{domain}", "Mattermost/Chat"),
        (f"https://mattermost.{domain}", "Mattermost"),
        (f"{base_url}:8065/", "Mattermost"),
        # Redmine (MEDIUM — project management)
        (f"https://redmine.{domain}", "Redmine"),
        (f"{base_url}:3000/projects", "Redmine"),
        # Zabbix (HIGH — monitoring infra)
        (f"https://zabbix.{domain}", "Zabbix"),
        (f"{base_url}:8080/zabbix/", "Zabbix"),
        # Nagios (HIGH — monitoring)
        (f"https://nagios.{domain}", "Nagios"),
        (f"{base_url}/nagios/", "Nagios"),
        # Graylog (HIGH — centralized logging)
        (f"{base_url}:9000/", "Graylog"),
        (f"https://graylog.{domain}", "Graylog"),
        # Rundeck (HIGH — job automation / RCE)
        (f"{base_url}:4440/", "Rundeck"),
        (f"https://rundeck.{domain}", "Rundeck"),
        # Superset (HIGH — BI dashboards + DB creds)
        (f"{base_url}:8088/", "Apache Superset"),
        (f"https://superset.{domain}", "Apache Superset"),
        # Metabase (HIGH — BI + DB connections)
        (f"{base_url}:3000/", "Metabase"),
        (f"https://metabase.{domain}", "Metabase"),
        # Ntopng (MEDIUM — network traffic analysis)
        (f"{base_url}:3000/", "ntopng"),
        # phpLDAPadmin (HIGH — directory access)
        (f"{base_url}:6443/", "phpLDAPadmin"),
        (f"https://ldap.{domain}", "LDAP Admin"),
        # Kafdrop (HIGH — Kafka topic browser)
        (f"{base_url}:9000/", "Kafdrop"),
        (f"https://kafdrop.{domain}", "Kafdrop"),
        # === UNCOMMON PORTS MOST HUNTERS MISS ===
        # Erlang Port Mapper (HIGH — distributed system access)
        (f"{base_url}:4369/", "Erlang EPMD"),
        # Hadoop YARN ResourceManager (CRITICAL — job submit = RCE)
        (f"{base_url}:8088/cluster", "Hadoop YARN"),
        (f"{base_url}:8088/ws/v1/cluster/apps", "Hadoop YARN Apps"),
        (f"{base_url}:50070/", "Hadoop NameNode"),
        (f"{base_url}:50075/", "Hadoop DataNode"),
        # HBase (HIGH — data access)
        (f"{base_url}:16010/", "HBase Master"),
        (f"{base_url}:16020/", "HBase RegionServer"),
        # Presto/Trino (HIGH — query engine)
        (f"{base_url}:8080/ui/", "Presto/Trino"),
        (f"{base_url}:8443/ui/", "Trino HTTPS"),
        # Druid (HIGH — analytics DB)
        (f"{base_url}:8888/unified-console.html", "Apache Druid"),
        (f"{base_url}:8081/druid/indexer/v1/tasks", "Druid Indexer"),
        # TensorBoard (MEDIUM — ML model data)
        (f"{base_url}:6006/", "TensorBoard"),
        # MLflow (HIGH — ML experiments + model registry)
        (f"{base_url}:5000/", "MLflow"),
        (f"{base_url}:5000/api/2.0/mlflow/experiments/list", "MLflow API"),
        # Ray Dashboard (HIGH — distributed compute)
        (f"{base_url}:8265/", "Ray Dashboard"),
        (f"{base_url}:8265/api/jobs/", "Ray Jobs API"),
        # Vector DBs on default ports
        (f"{base_url}:6333/collections", "Qdrant Vector DB"),
        (f"{base_url}:19530/", "Milvus Vector DB"),
        (f"{base_url}:8080/v1/schema", "Weaviate Vector DB"),
        # Label Studio (HIGH — annotated training data)
        (f"{base_url}:8080/user/login", "Label Studio"),
        # Triton Inference Server (HIGH — model serving)
        (f"{base_url}:8000/v2/models", "Triton Inference"),
        (f"{base_url}:8001/", "Triton gRPC"),
        # BentoML (HIGH — ML model serving)
        (f"{base_url}:3000/", "BentoML"),
        # OpenFaaS (HIGH — serverless functions)
        (f"{base_url}:8080/system/functions", "OpenFaaS"),
        (f"https://faas.{domain}", "OpenFaaS"),
        # Kiali (HIGH — Istio service mesh viz)
        (f"{base_url}:20001/", "Kiali"),
        (f"https://kiali.{domain}", "Kiali"),
        # Istio/Envoy admin ports
        (f"{base_url}:15014/metrics", "Istio Metrics"),
        (f"{base_url}:9901/", "Envoy Admin"),
        (f"{base_url}:9901/config_dump", "Envoy Config Dump"),
        # Loki (HIGH — log aggregation)
        (f"{base_url}:3100/", "Grafana Loki"),
        (f"{base_url}:3100/loki/api/v1/labels", "Loki API"),
        (f"https://loki.{domain}", "Grafana Loki"),
        # Thanos (HIGH — Prometheus long-term storage)
        (f"{base_url}:10902/", "Thanos"),
        (f"{base_url}:10902/graph", "Thanos Query"),
        # AlertManager (MEDIUM — alert config)
        (f"{base_url}:9093/", "AlertManager"),
        (f"{base_url}:9093/api/v1/alerts", "AlertManager API"),
        (f"https://alertmanager.{domain}", "AlertManager"),
        # Pushgateway (MEDIUM — metrics endpoint)
        (f"{base_url}:9091/", "Pushgateway"),
        # Blackbox Exporter (MEDIUM — probe config)
        (f"{base_url}:9115/", "Blackbox Exporter"),
        # Webmin (CRITICAL — server admin panel)
        (f"{base_url}:10000/", "Webmin"),
        # cPanel/WHM (CRITICAL — hosting panel)
        (f"{base_url}:2082/", "cPanel"),
        (f"{base_url}:2083/", "cPanel SSL"),
        (f"{base_url}:2086/", "WHM"),
        (f"{base_url}:2087/", "WHM SSL"),
        # Splunk (HIGH — SIEM data)
        (f"{base_url}:8089/", "Splunk"),
        (f"https://splunk.{domain}", "Splunk"),
        # TeamCity (HIGH — CI/CD secrets)
        (f"{base_url}:8111/", "TeamCity"),
        (f"https://teamcity.{domain}", "TeamCity"),
        # Bamboo (HIGH — CI/CD)
        (f"https://bamboo.{domain}", "Bamboo"),
        # Nexus Repository (HIGH — artifacts)
        (f"{base_url}:8081/", "Nexus Repository"),
        (f"https://nexus.{domain}", "Nexus Repository"),
        # Artifactory (HIGH — build artifacts)
        (f"{base_url}:8081/artifactory/", "JFrog Artifactory"),
        (f"https://artifactory.{domain}", "JFrog Artifactory"),
        # WildFly/JBoss Admin (CRITICAL — deploy = RCE)
        (f"{base_url}:9990/", "WildFly Admin"),
        (f"{base_url}:9990/console/", "JBoss Console"),
        # Tomcat Manager (CRITICAL — deploy = RCE)
        (f"{base_url}:8080/manager/html", "Tomcat Manager"),
        (f"{base_url}:8080/host-manager/html", "Tomcat Host Manager"),
        # WebLogic Admin (CRITICAL — RCE)
        (f"{base_url}:7001/console/", "WebLogic Console"),
        (f"{base_url}:7002/console/", "WebLogic SSL Console"),
        # GlassFish Admin (HIGH)
        (f"{base_url}:4848/", "GlassFish Admin"),
    ]

    safe_print(f"{CYAN}[*] Testing {len(check_list)} port-based URLs{NC}")
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(check_url, url, name): url for url, name in check_list}
        concurrent.futures.wait(futures)


def check_saas_platforms(company, base_url, permutations):
    """Enterprise SaaS & IdP checks with permutation support."""
    safe_print(f"\n{GREEN}--- Enterprise SaaS & IdP (Permutated) ---{NC}")

    checks = []
    # Base URL checks (no permutation needed)
    checks.append((f"{base_url}/app/etc/local.xml", "Magento Config Leak"))

    # Subdomain-based checks (use permutations)
    for perm in permutations:
        checks.append((f"https://{perm}.service-now.com/kb_view.do", "ServiceNow KB"))
        checks.append((f"https://{perm}.service-now.com/sp_widget_list.do", "ServiceNow Widgets"))
        checks.append((f"https://{perm}.my.salesforce.com/aura", "Salesforce Lightning"))
        checks.append((f"https://{perm}.force.com", "Salesforce Sites"))
        checks.append((f"https://auth.{perm}.com/auth/realms/master/.well-known/openid-configuration", "Keycloak Realm"))
        checks.append((f"https://gitlab.{perm}.com/explore", "GitLab Explore"))
        checks.append((f"https://{perm}.okta.com/.well-known/openid-configuration", "Okta Tenant"))
        checks.append((f"https://{perm}.auth0.com/.well-known/openid-configuration", "Auth0 Tenant"))

    safe_print(f"{CYAN}[*] Testing {len(checks)} SaaS URLs{NC}")
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(check_url, url, name): url for url, name in checks}
        concurrent.futures.wait(futures)


def check_idp_cms(base_url, company, permutations):
    """IdP and CMS Logic checks with permutation support."""
    safe_print(f"\n{GREEN}--- IdP & CMS Logic (Permutated) ---{NC}")

    checks = []
    # Base URL checks
    checks.append((f"{base_url}/wp-json/wp/v2/users", "WordPress Users"))
    checks.append((f"{base_url}/wp-admin/setup-config.php", "WordPress Setup"))
    checks.append((f"{base_url}/core/install.php", "Drupal Installer"))
    checks.append((f"{base_url}/user/register", "Drupal Registration"))

    # Subdomain-based (permutated)
    for perm in permutations:
        checks.append((f"https://{perm}.okta.com/api/v1/users", "Okta API Users"))
        checks.append((f"https://auth.{perm}.com/auth/realms/master/account/", "Keycloak Registration"))

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(check_url, url, name): url for url, name in checks}
        concurrent.futures.wait(futures)


def check_intigriti_mapper(base_url, company, permutations):
    """Intigriti mapper with permutation support."""
    safe_print(f"\n{GREEN}--- Intigriti Mapper Targets (Permutated) ---{NC}")

    checks = []
    # Base URL checks
    checks.append((f"{base_url}/telescope/requests", "Laravel Telescope"))
    checks.append((f"{base_url}/jenkins/signup", "Jenkins Signup (Path)"))
    checks.append((f"{base_url}/jenkins/script", "Jenkins Script Console (Path)"))

    # Subdomain-based (permutated)
    for perm in permutations:
        checks.append((f"https://{perm}.freshservice.com/support/signup", "Freshservice Signup"))
        checks.append((f"https://jenkins.{perm}.com/signup", "Jenkins Signup"))
        checks.append((f"https://jenkins.{perm}.com/script", "Jenkins Script Console"))
        checks.append((f"https://gitlab.{perm}.com/explore/snippets", "GitLab Snippets"))

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(check_url, url, name): url for url, name in checks}
        concurrent.futures.wait(futures)


# --- TLD List for -org mode ---
COMMON_TLDS = [
    ".com", ".net", ".org", ".io", ".co", ".dev", ".app", ".ai",
    ".cloud", ".tech", ".info", ".biz", ".us", ".eu", ".uk", ".de",
    ".in", ".ca", ".xyz", ".me", ".tv", ".cc", ".one",
]


def generate_permutations(company):
    """Generate bucket/subdomain permutations from a company name."""
    suffixes = [
        "", "dev", "development", "stage", "staging", "test", "testing",
        "prod", "production", "internal", "corp", "admin", "assets", "media",
        "static", "images", "files", "backup", "backups", "archive", "ops",
        "devops", "sec", "security", "logs", "db", "database", "uploads",
    ]
    prefixes = ["", "dev-", "test-", "admin-", "internal-", "corp-"]
    separators = ["", "-", "."]

    perm_set = set()
    for pre in prefixes:
        for suffix in suffixes:
            for sep in separators:
                if not pre and not suffix:
                    perm_set.add(company)
                elif not pre:
                    perm_set.add(f"{company}{sep}{suffix}")
                elif not suffix:
                    perm_set.add(f"{pre}{company}")
                else:
                    perm_set.add(f"{pre}{company}{sep}{suffix}")
    return sorted(perm_set)


def extract_company_from_domain(domain):
    """Extract company name from a domain, stripping common prefixes."""
    parts = domain.split(".")
    skip = {"www", "api", "app", "dev", "staging", "m", "mobile", "mail", "ftp"}
    clean = [p for p in parts if p not in skip]
    if len(clean) >= 2:
        return clean[-2]
    elif clean:
        return clean[0]
    return parts[0]


def classify_input(raw):
    """
    Classify a single input string and return (input_type, company, domain, base_url).
    input_type is one of: 'url', 'domain', 'company'
    """
    raw = raw.strip().rstrip("/")
    if not raw or raw.startswith("#"):
        return None, None, None, None

    # URL
    if re.match(r"^https?://", raw):
        parsed = urlparse(raw)
        domain = parsed.hostname or ""
        base_url = f"{parsed.scheme}://{domain}"
        company = extract_company_from_domain(domain)
        return "url", company, domain, base_url

    # Domain (has a dot and looks like a hostname)
    if "." in raw and not " " in raw:
        domain = raw
        base_url = f"https://{domain}"
        company = extract_company_from_domain(domain)
        return "domain", company, domain, base_url

    # Company name
    company = raw.lower().strip()
    return "company", company, None, None


def run_scan_for_target(input_type, company, domain, base_url, permutations, checks):
    """Run scan workflow for a single target. `checks` is a set of enabled categories."""
    safe_print(f"\n{CYAN}{'='*60}{NC}")
    safe_print(f"{CYAN} Scanning: {company} | Type: {input_type}{NC}")
    safe_print(f"{CYAN} Domain: {domain or 'auto-TLD'} | Base: {base_url or 'auto-TLD'}{NC}")
    safe_print(f"{CYAN} Permutations: {len(permutations)}{NC}")
    safe_print(f"{CYAN} Checks: {', '.join(sorted(checks))}{NC}")
    safe_print(f"{CYAN}{'='*60}{NC}")

    # --- If input_type is 'company', run TLD discovery first ---
    base_urls_to_scan = []
    domains_to_scan = []

    if input_type == "company":
        safe_print(f"\n{GREEN}--- Auto-TLD Discovery for '{company}' ---{NC}")
        tld_results = []

        def probe_tld(tld):
            test_domain = f"{company}{tld}"
            test_url = f"https://{test_domain}"
            try:
                r = requests.head(test_url, headers={"User-Agent": USER_AGENT},
                                  timeout=5, allow_redirects=True, verify=False)
                if r.status_code < 500:
                    tld_results.append((test_domain, test_url))
                    safe_print(f"{GREEN}  [+] LIVE: {test_url} ({r.status_code}){NC}")
            except:
                pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(probe_tld, COMMON_TLDS)

        if tld_results:
            for d, u in tld_results:
                domains_to_scan.append(d)
                base_urls_to_scan.append(u)
            safe_print(f"{CYAN}[+] Found {len(tld_results)} live TLD(s){NC}")
        else:
            fallback_domain = f"{company}.com"
            domains_to_scan.append(fallback_domain)
            base_urls_to_scan.append(f"https://{fallback_domain}")
            safe_print(f"{YELLOW}[!] No live TLDs found, falling back to {fallback_domain}{NC}")
    else:
        domains_to_scan.append(domain)
        base_urls_to_scan.append(base_url)

    # --- Run selected check categories ---

    if "buckets" in checks:
        scan_cloud_buckets(permutations)
        safe_print(f"\n{GREEN}--- Firebase DB Check ---{NC}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = {executor.submit(check_firebase_db, perm): perm for perm in permutations}
            concurrent.futures.wait(futures)

    for i, (scan_domain, scan_base) in enumerate(zip(domains_to_scan, base_urls_to_scan)):
        if len(base_urls_to_scan) > 1:
            safe_print(f"\n{CYAN}>>> Scanning domain [{i+1}/{len(base_urls_to_scan)}]: {scan_domain}{NC}")

        if "web" in checks:
            check_app_vulns(scan_base)
            check_unique_vulns(scan_base)
            check_jira(scan_base, company)
            check_overlooked(scan_base, scan_domain)
            check_ai_ml(scan_base)

        if "ports" in checks:
            check_databases(scan_base, scan_domain)
            check_infra_dashboards(scan_base, scan_domain)

        if "saas" in checks:
            check_idp_cms(scan_base, company, permutations)
            check_intigriti_mapper(scan_base, company, permutations)

    if "saas" in checks:
        check_third_party(company, permutations)
        check_saas_platforms(company, base_urls_to_scan[0] if base_urls_to_scan else f"https://{company}.com", permutations)


def print_summary():
    """Print a clean summary of all confirmed findings."""
    if not findings:
        safe_print(f"\n{GREEN}{'='*60}{NC}")
        safe_print(f"{GREEN} Scan Complete - No confirmed findings{NC}")
        safe_print(f"{GREEN}{'='*60}{NC}")
        return

    safe_print(f"\n{RED}{'='*60}{NC}")
    safe_print(f"{RED} SCAN SUMMARY - {len(findings)} Finding(s){NC}")
    safe_print(f"{RED}{'='*60}{NC}")

    for i, f in enumerate(findings, 1):
        color = RED if f["severity"] == "CRITICAL" else YELLOW
        safe_print(f"{color}  [{i}] [{f['severity']}] {f['check_type']}{NC}")
        safe_print(f"       URL: {f['url']}")
        if f["detail"]:
            safe_print(f"       Detail: {f['detail']}")
        safe_print("")


def main():
    parser = argparse.ArgumentParser(
        description="Enhanced Cloud Bucket & Misconfiguration Scanner v3.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Target flags (required - pick one):
  -org uber             Scan 'uber' as org (auto-TLD + permutations)
  -org uber.com         Scan specific domain
  -org https://x.com    Scan specific URL
  -list targets.txt     Batch scan from file (one target per line)

Check category flags (optional - pick one or more):
  -p                    Port-based checks only (DB panels, infra dashboards)
  -b                    Cloud bucket + Firebase checks only
  -w                    Web app vulnerability checks only (git, env, swagger, etc.)
  -s                    SaaS & third-party integration checks only

  If NO category flag is given, ALL checks run by default.

Examples:
  python bucket_finder.py -org uber                 Run ALL checks on uber
  python bucket_finder.py -org uber -p              Port scan only
  python bucket_finder.py -org uber -p -b           Ports + buckets
  python bucket_finder.py -list targets.txt -w -s   Web + SaaS on all targets
        """
    )
    parser.add_argument("-org", dest="org", help="Single target: company name, domain, or URL")
    parser.add_argument("-list", dest="listfile", help="File with targets (one per line)")
    parser.add_argument("-p", dest="ports", action="store_true", help="Port-based checks (DBs, infra dashboards)")
    parser.add_argument("-b", dest="buckets", action="store_true", help="Cloud bucket + Firebase checks")
    parser.add_argument("-w", dest="web", action="store_true", help="Web app vulns (git, env, swagger, debug)")
    parser.add_argument("-s", dest="saas", action="store_true", help="SaaS & third-party checks")

    # Backward compat positional
    parser.add_argument("target", nargs="?", help="Target (backward compat, same as -org)")

    args = parser.parse_args()

    # Determine which check categories to run
    checks = set()
    if args.ports:
        checks.add("ports")
    if args.buckets:
        checks.add("buckets")
    if args.web:
        checks.add("web")
    if args.saas:
        checks.add("saas")

    # If no category flags given, run ALL
    if not checks:
        checks = {"ports", "buckets", "web", "saas"}

    # Determine targets
    targets = []
    if args.listfile:
        if not os.path.isfile(args.listfile):
            print(f"{RED}[!] File not found: {args.listfile}{NC}")
            sys.exit(1)
        with open(args.listfile, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)
        if not targets:
            print(f"{RED}[!] No targets found in {args.listfile}{NC}")
            sys.exit(1)
        safe_print(f"{CYAN}[+] Loaded {len(targets)} target(s) from {args.listfile}{NC}")
    elif args.org:
        targets.append(args.org)
    elif args.target:
        targets.append(args.target)
    else:
        parser.print_help()
        sys.exit(1)

    safe_print(f"\n{CYAN}{'='*60}{NC}")
    safe_print(f"{CYAN}  Enhanced Bucket & Misconfig Scanner v3.0{NC}")
    safe_print(f"{CYAN}  Targets: {len(targets)} | Threads: {MAX_THREADS}{NC}")
    safe_print(f"{CYAN}  Checks:  {', '.join(sorted(checks)).upper()}{NC}")
    safe_print(f"{CYAN}{'='*60}{NC}")

    for idx, raw_target in enumerate(targets, 1):
        if len(targets) > 1:
            safe_print(f"\n{CYAN}{'#'*60}{NC}")
            safe_print(f"{CYAN}# TARGET [{idx}/{len(targets)}]: {raw_target}{NC}")
            safe_print(f"{CYAN}{'#'*60}{NC}")

        input_type, company, domain, base_url = classify_input(raw_target)
        if input_type is None:
            continue

        permutations = generate_permutations(company)
        if input_type == "company":
            safe_print(f"{GREEN}[+] Mode: ORG | Company: {company}{NC}")
            safe_print(f"{CYAN}[+] Auto-TLD will probe: {', '.join(COMMON_TLDS[:8])}...{NC}")
        elif input_type == "domain":
            safe_print(f"{GREEN}[+] Mode: DOMAIN | {domain} (company: {company}){NC}")
        else:
            safe_print(f"{GREEN}[+] Mode: URL | {base_url} (company: {company}){NC}")
        safe_print(f"{CYAN}[+] Generated {len(permutations)} permutations{NC}")

        run_scan_for_target(input_type, company, domain, base_url, permutations, checks)

    # Final Summary
    print_summary()


if __name__ == "__main__":
    main()
