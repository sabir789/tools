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
import time
import signal
import socket
from urllib.parse import urlparse
import urllib3
from datetime import datetime

# Disable SSL warnings for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Colors ---
GREEN  = '\033[0;32m'
YELLOW = '\033[1;33m'
RED    = '\033[0;31m'
CYAN   = '\033[0;36m'
NC     = '\033[0m'

# --- Config ---
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 (0xsabir@wearehackerone.com)"
TIMEOUT = 7
MAX_THREADS = 30
HOST_PARALLEL = 10  # How many hosts to scan simultaneously

HEADERS = {
    "User-Agent": USER_AGENT,
    "X-Bug-Bounty": "0xsabir@wearehackerone.com",
}

# --- Global Output Lock ---
print_lock = threading.Lock()
findings_lock = threading.Lock()
file_lock = threading.Lock()
findings = []  # Collect all results

# --- Real-time output files (set in main) ---
OUTPUT_LIVE_FILE = None      # Live hosts/subdomains
OUTPUT_PORTS_FILE = None     # Live ports found open
OUTPUT_FINDINGS_FILE = None  # Confirmed findings

# Dedup sets for live hosts/ports
seen_live_hosts = set()
seen_live_ports = set()

# --- Progress Tracker ---
request_counter = 0
hosts_probed = 0
hosts_alive = 0
hosts_dead = 0
counter_lock = threading.Lock()
scan_start_time = None
shutdown_flag = threading.Event()  # Clean Ctrl+C

def increment_counter():
    """Increment request counter and print progress."""
    global request_counter
    with counter_lock:
        request_counter += 1
        count = request_counter
    # Print progress every 10 requests
    if count % 10 == 0:
        elapsed = time.time() - scan_start_time if scan_start_time else 0
        rate = count / elapsed if elapsed > 0 else 0
        sys.stderr.write(f"\r\033[K\033[36m[PROGRESS] {count} reqs | {rate:.0f}/s | {hosts_alive} live | {hosts_dead} dead | {elapsed:.0f}s\033[0m")
        sys.stderr.flush()


probe_errors_logged = 0

def probe_host(url):
    """Quick liveness check using socket connection (port 443, then 80)."""
    if shutdown_flag.is_set():
        return False
    global hosts_probed, hosts_alive, hosts_dead, probe_errors_logged
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        if not hostname:
            with counter_lock:
                hosts_probed += 1
                hosts_dead += 1
            return False
    except:
        with counter_lock:
            hosts_probed += 1
            hosts_dead += 1
        return False

    # Try TCP connect to port 443, then 80
    for port in [443, 80]:
        try:
            sock = socket.create_connection((hostname, port), timeout=3)
            sock.close()
            with counter_lock:
                hosts_probed += 1
                hosts_alive += 1
            return True
        except:
            pass

    # Both ports failed — try HTTP HEAD as last resort
    try:
        r = requests.head(url, headers=HEADERS, timeout=3, allow_redirects=True, verify=False)
        with counter_lock:
            hosts_probed += 1
            hosts_alive += 1
        return True
    except Exception as e:
        with counter_lock:
            hosts_probed += 1
            hosts_dead += 1
            # Log first 3 errors for debugging
            if probe_errors_logged < 3:
                probe_errors_logged += 1
                safe_print(f"{YELLOW}[DEBUG] Probe failed for {hostname}: {type(e).__name__}: {e}{NC}")
        return False

def safe_print(message):
    with print_lock:
        print(message)

def write_to_output(filepath, line):
    """Thread-safe append to output file in real-time."""
    if not filepath:
        return
    with file_lock:
        with open(filepath, "a", encoding="utf-8") as f:
            f.write(line + "\n")

def record_live_host(host):
    """Record a live host/subdomain/IP to the live targets file."""
    with file_lock:
        if host not in seen_live_hosts:
            seen_live_hosts.add(host)
            if OUTPUT_LIVE_FILE:
                with open(OUTPUT_LIVE_FILE, "a", encoding="utf-8") as f:
                    f.write(host + "\n")

def record_live_port(url, service_name):
    """Record a live port to the ports file."""
    key = url
    with file_lock:
        if key not in seen_live_ports:
            seen_live_ports.add(key)
            if OUTPUT_PORTS_FILE:
                with open(OUTPUT_PORTS_FILE, "a", encoding="utf-8") as f:
                    f.write(f"{url} [{service_name}]\n")

def add_finding(severity, check_type, url, status, detail=""):
    with findings_lock:
        findings.append({
            "severity": severity,
            "check_type": check_type,
            "url": url,
            "status": status,
            "detail": detail
        })
    # Real-time write to findings file
    line = f"[{severity}] [{check_type}] {url}"
    if detail:
        line += f" | {detail}"
    write_to_output(OUTPUT_FINDINGS_FILE, line)

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
    "Spring Boot Actuator": {
        "condition": "or",
        "words": ['"status":', '"beans":', '"contextId":'],
        "headers": {"content-type": "json"}
    },
    "Spring Boot Heapdump": [],  # Binary file
    "Spring Boot Env": {
        "condition": "or",
        "words": ['"propertySources":', '"activeProfiles":'],
        "headers": {"content-type": "json"}
    },
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
    "Jupyter": {
        "condition": "and",
        "words": ["jupyter"],
        "regex": [r"data-base-url"]
    },
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
CONFIRM_SIGNATURES.update({    # --- ADDED TO ENSURE ZERO FALSE POSITIVES ---
    "ActiveMQ Admin": ["activemq", "broker"],
    "Airflow": ["airflow", "dags"],
    "AlertManager": ["alertmanager", "prometheus"],
    "AlertManager API": ["status", "data"],
    "Apache Druid": ["druid", "coordinator"],
    "Apache Flink": ["flink", "taskmanagers"],
    "Apache Flink Dashboard": ["flink", "taskmanagers"],
    "Apache NiFi": ["nifi", "canvas"],
    "Apache NiFi HTTPS": ["nifi", "canvas"],
    "Apache Server Status": ["apache server status", "total accesses"],
    "Apache Solr": ["solr", "lucenecore"],
    "Apache Storm UI": ["storm ui", "topology"],
    "Apache Superset": ["superset", "dashboards"],
    "ArangoDB Web UI": ["arangodb", "foxx"],
    "Argo Workflows": ["argo", "workflows"],
    "Atlassian Cloud": ["atlassian"],
    "Bamboo": ["bamboo", "atlassian"],
    "BentoML": ["bentoml"],
    "Blackbox Exporter": ["blackbox exporter"],
    "CI Server": ["jenkins", "gitlab", "bamboo", "teamcity"],
    "Celery Flower": ["flower", "celery"],
    "ClickHouse Databases": ["system", "default"],
    "ClickHouse HTTP": ["ok."],
    "Cockpit": ["cockpit", "server"],
    "Composer Config": ["require", "autoload"],
    "Confluence": ["confluence", "atlassian"],
    "Consul": ["consul"],
    "Consul KV Store": ["key", "value"],
    "Consul UI": ["consul"],
    "Container Registry": ["repositories"],
    "Couchbase Buckets": ["buckets"],
    "Couchbase Console": ["couchbase"],
    "Docker API (TLS)": ["containers", "image"],
    "Docker API (Unauth)": ["containers", "image"],
    "Docker API Images": ["repoTags", "size"],
    "Drone CI": ["drone", "pipelines"],
    "Druid Indexer": ["indexer", "tasks"],
    "Drupal Installer": ["drupal", "install"],
    "Drupal Registration": ["drupal", "register"],
    "Envoy Admin": ["envoy", "server_info"],
    "Envoy Config Dump": ["configs"],
    "Erlang EPMD": ["name", "port"],
    "Freshservice Signup": ["freshservice"],
    "GitLab": ["gitlab"],
    "GitLab CI Config": ["stages", "script"],
    "Gitea": ["gitea", "explore"],
    "GlassFish Admin": ["glassfish", "admin"],
    "Grafana Datasources": ["type", "url", "access"],
    "Grafana Loki": ["loki", "grafana"],
    "Graylog": ["graylog"],
    "HBase Master": ["hbase", "master"],
    "HBase RegionServer": ["hbase", "regionserver"],
    "Hadoop DataNode": ["hadoop", "datanode"],
    "Hadoop NameNode": ["hadoop", "namenode"],
    "Hadoop YARN": ["hadoop", "yarn", "cluster"],
    "Hadoop YARN Apps": ["apps", "app"],
    "Harbor Registry": ["harbor"],
    "HashiCorp Vault": ["vault", "hashicorp"],
    "Hazelcast": ["hazelcast", "cluster"],
    "Istio Metrics": ["istio", "metrics"],
    "JBoss Console": ["jboss", "management"],
    "JFrog Artifactory": ["artifactory", "jfrog"],
    "Jaeger": ["jaeger"],
    "Jaeger UI": ["jaeger"],
    "Jenkins": ["jenkins"],
    "Jenkins Manage": ["jenkins", "manage"],
    "Jenkins Signup": ["jenkins", "signup"],
    "Jenkins Signup (Path)": ["jenkins", "signup"],
    "Jira Admin Contact": ["jira", "contact"],
    "Jira Dashboard": ["jira", "dashboard"],
    "Jira Filters": ["jira", "filters"],
    "Jira Portal Config": ["jira", "portal"],
    "Jira Service Desk Signup": ["jira", "signup"],
    "Jira User Enum": ["jira", "user"],
    "Jira User Picker API": ["users:", "total:"],
    "Jupyter Notebook": ["jupyter"],
    "Kafdrop": ["kafdrop", "kafka"],
    "Kafka Control Center": ["confluent", "control center"],
    "Kafka UI": ["kafka", "ui"],
    "Keycloak Registration": ["keycloak", "register"],
    "Kiali": ["kiali"],
    "Kubelet API": ["items", "metadata"],
    "Kubelet Read-Only API (Unauth)": ["items", "metadata"],
    "Kubernetes Config": ["apiVersion: v1", "clusters"],
    "LDAP Admin": ["ldapadmin", "phpldapadmin"],
    "Label Studio": ["label studio"],
    "Loki API": ["status", "data"],
    "MLflow API": ["experiments"],
    "Mattermost": ["mattermost"],
    "Mattermost/Chat": ["mattermost"],
    "Memcached": ["stats", "version", "pid"],
    "Metabase": ["metabase"],
    "Milvus Vector DB": ["custom_setup", "msg"],
    "MinIO/S3": ["minio", "s3"],
    "MongoDB": ["mongodb", "ok"],
    "NATS Connections": ["connections"],
    "NATS Monitoring": ["nats", "varz"],
    "Nagios": ["nagios"],
    "Neo4j Bolt": ["neo4j", "bolt"],
    "Neo4j Browser": ["neo4j"],
    "Nexus Repository": ["nexus", "repository"],
    "Node Package Config": ["name:", "version:"],
    "Nomad Jobs API": ["ID", "Name", "Type"],
    "Nomad UI": ["nomad", "jobs"],
    "Okta API Users": ["profile", "credentials"],
    "Open bucket with listing": ["ListBucketResult"],
    "OpenFaaS": ["openfaas", "functions"],
    "OpenSearch": ["opensearch", "cluster_name"],
    "OpenSearch Dashboards": ["opensearch", "dashboards"],
    "PHP Info": ["phpinfo()", "PHP Version"],
    "PgAdmin": ["pgadmin"],
    "Presto/Trino": ["presto", "trino"],
    "Prometheus Targets": ["activeTargets", "droppedTargets"],
    "Pushgateway": ["pushgateway", "prometheus"],
    "Qdrant Vector DB": ["collections"],
    "RabbitMQ": ["rabbitmq"],
    "Rails DB Config": ["adapter:", "database:"],
    "Ray Dashboard": ["ray", "dashboard"],
    "Ray Jobs API": ["job_id", "status"],
    "Redis": ["redis_version", "role"],
    "Redmine": ["redmine"],
    "RethinkDB Web UI": ["rethinkdb", "admin"],
    "Rundeck": ["rundeck"],
    "SVN Repository": ["svn", "dir\n"],
    "Salesforce Lightning": ["salesforce", "aura"],
    "ServiceNow Widgets": ["servicenow", "widgets"],
    "Slack Workspace": ["slack"],
    "Solr Cores": ["status", "core"],
    "SonarQube": ["sonarqube"],
    "Spark History Server": ["spark", "history"],
    "Spark Jobs UI (Unauth)": ["spark", "jobs"],
    "Spark Master UI (Unauth)": ["spark", "master"],
    "Spark Worker UI (Unauth)": ["spark", "worker"],
    "Splunk": ["splunk"],
    "Spring Boot Admin": ["spring", "admin"],
    "TeamCity": ["teamcity"],
    "Thanos": ["thanos"],
    "Thanos Query": ["thanos", "query"],
    "Tomcat Host Manager": ["tomcat", "host manager"],
    "Tomcat Manager": ["tomcat", "manager"],
    "Traefik API": ["routers", "services"],
    "Traefik Dashboard": ["traefik", "dashboard"],
    "Trino HTTPS": ["trino"],
    "Triton Inference": ["models", "name"],
    "Triton gRPC": ["triton", "grpc"],
    "Vault Seal Status": ["sealed:"],
    "Verdaccio npm Registry": ["verdaccio"],
    "WHM": ["whm", "cpanel"],
    "WHM SSL": ["whm", "cpanel"],
    "WP Config Backup": ["define('DB_PASSWORD'", "define('DB_USER'"],
    "Weave Scope": ["weave", "scope"],
    "Weaviate Vector DB": ["classes", "schema"],
    "WebLogic Console": ["weblogic", "console"],
    "WebLogic SSL Console": ["weblogic", "console"],
    "Webmin": ["webmin"],
    "Werkzeug Debug Console (RCE)": ["werkzeug", "console"],
    "WildFly Admin": ["wildfly", "admin"],
    "WordPress Setup": ["wordpress", "setup"],
    "Zabbix": ["zabbix"],
    "Zendesk": ["zendesk"],
    "Zipkin": ["zipkin"],
    "Zookeeper": ["zookeeper"],
    "cAdvisor Node Metrics": ["cadvisor", "metrics"],
    "cPanel": ["cpanel"],
    "cPanel SSL": ["cpanel"],
    "etcd": ["etcdserver", "etcdcluster"],
    "etcd Keys": ["action", "node"],
    "npm Registry": ["db_name", "doc_count"],
    "ntopng": ["ntopng"],
    "phpLDAPadmin": ["phpldapadmin"],
}
)


def is_false_positive(response_text, check_type, content_type="", headers=None, status_code=200):
    """
    Determines if a 200 response is a false positive by analyzing content.
    Returns True if it's considered a false positive.
    Returns False ONLY if it is a fully CONFIRMED finding (Zero False Positives).
    """
    if not response_text:
        return True  # Empty response is not a real finding

    text_lower = response_text[:10000].lower()  # Check up to 10KB
    
    # 1. Any known false positive signature immediately invalidates it (strict mode)
    for sig in FALSE_POSITIVE_SIGNATURES:
        if sig in text_lower:
            return True
            
    # 2. Strict Confirmation: If it's in CONFIRM_SIGNATURES, ensure it matches!
    if check_type in CONFIRM_SIGNATURES:
        sigs = CONFIRM_SIGNATURES[check_type]
        if not sigs:
            # Empty signature list -> highly varying / binary data
            if content_type and "text/html" in content_type:
                return True # HTML from a binary/data check is a false positive
            return False

        if isinstance(sigs, dict):
            # Nuclei-style matcher
            condition = sigs.get("condition", "or").lower()
            words = sigs.get("words", [])
            regexes = sigs.get("regex", [])
            expected_headers = sigs.get("headers", {})
            expected_status = sigs.get("status", [])

            if expected_status and status_code not in expected_status:
                return True

            if expected_headers:
                if not headers:
                    return True
                headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
                for h_k, h_v in expected_headers.items():
                    actual_v = headers_lower.get(h_k.lower(), "")
                    if h_v.lower() not in actual_v:
                        return True

            matched_words = [w for w in words if w.lower() in text_lower]
            matched_regexes = [r for r in regexes if re.search(r, text_lower, re.IGNORECASE)]

            total_matched = len(matched_words) + len(matched_regexes)
            total_required = len(words) + len(regexes)

            if total_required > 0:
                if condition == "and":
                    if total_matched < total_required:
                        return True
                else: # condition == "or"
                    if total_matched == 0:
                        return True

            return False  # CONFIRMED!

        else:
            # Match at least ONE signature
            for sig in sigs:
                if sig.lower() in text_lower:
                    return False  # CONFIRMED!
                    
            # If no signature matched, it's a false positive (Zero-FP rule)
            return True

    # 3. For any unaccounted checks, assume it's a false positive if it returns HTML
    if content_type and "text/html" in content_type:
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
    Records live hosts and open ports in real-time.
    """
    if shutdown_flag.is_set():
        return False, url, 0
    increment_counter()
    try:
        # First request: DON'T follow redirects to see the real status
        response = requests.get(
            url,
            headers=HEADERS,
            timeout=TIMEOUT,
            allow_redirects=False,
            verify=False
        )
        status = response.status_code

        # --- Real-time recording: live host + open port ---
        if status < 500:
            try:
                parsed = urlparse(url)
                host = parsed.hostname or ""
                port = parsed.port
                # Record the host as live
                if host:
                    record_live_host(host)
                # If there's a non-standard port, record it as a live port
                if port and port not in (80, 443):
                    record_live_port(f"{parsed.scheme}://{host}:{port}", check_type)
            except:
                pass

        # Handle redirects explicitly
        if status in [301, 302, 303, 307, 308]:
            location = response.headers.get("Location", "unknown")
            if "Bucket" in check_type:
                # AWS S3 and others redirect to regional endpoints if the bucket exists
                safe_print(f"{YELLOW}[*] {check_type} EXISTS (Redirect) -> {url} => {location}{NC}")
                add_finding("INFO", "Bucket Extists (Redirect)", url, status, f"Redirects to {location}")
                return True, url, status
            # Non-bucket checks
            if any(kw in location.lower() for kw in ["login", "signin", "auth", "sso", "account"]):
                # Redirect to login = not a real finding, just skip silently
                return False, url, status
            else:
                safe_print(f"{YELLOW}[>] {check_type} REDIRECT ({status}) -> {url} => {location}{NC}")
                return False, url, status

        elif status == 400 and "Bucket" in check_type:
            # AWS S3 sometimes returns 400 Bad Request if you hit a global endpoint for a bucket requiring a specific region
            region = response.headers.get("x-amz-bucket-region")
            if region or "The bucket you are attempting to access must be addressed using the specified endpoint" in response.text:
                safe_print(f"{YELLOW}[*] {check_type} EXISTS but requires regional endpoint (400) -> {url} [Region: {region or 'unknown'}]{NC}")
                add_finding("INFO", "Bucket Exists", url, status, f"Region: {region}")
                return True, url, status
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
                    if is_false_positive(body, check_type, content_type, response.headers, status):
                        return False, url, status
                    safe_print(f"{RED}[!!!] {check_type} FOUND (200) -> {url}{NC}")
                    add_finding("HIGH", check_type, url, status)
                    return True, url, status
            else:
                # Non-bucket checks: validate content to reduce false positives
                if is_false_positive(body, check_type, content_type, response.headers, status):
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
    # By using GLOBAL endpoints we avoid 40+ redundant regional requests per permutation
    templates = [
        # AWS S3 (Global endpoint handles routing/redirects to regions)
        "https://{}.s3.amazonaws.com",
        "https://s3.amazonaws.com/{}",
        # GCS (Global)
        "https://storage.googleapis.com/{}",
        "https://{}.storage.googleapis.com",
        "https://firebasestorage.googleapis.com/v0/b/{}/o",
        # Azure (Global)
        "https://{}.blob.core.windows.net",
        "https://{}.blob.core.windows.net/?comp=list",
        "https://{}.blob.core.windows.net/public",
    ]

    # For providers lacking global routing, we check the most common top regions
    # (Checking 20+ regions per provider generates too much noise/slowness)
    do_regions = ["nyc3", "ams3", "sgp1", "fra1"]       # Top 4 DigitalOcean
    linode_regions = ["us-east-1", "eu-central-1"]      # Top 2 Linode
    alibaba_regions = ["cn-hangzhou", "ap-southeast-1"] # Top 2 Alibaba
    
    for region in do_regions:
        templates.append(f"https://{{}}.{region}.digitaloceanspaces.com")
    for region in linode_regions:
        templates.append(f"https://{{}}.{region}.linodeobjects.com")
    for region in alibaba_regions:
        templates.append(f"https://{{}}.oss-{region}.aliyuncs.com")

    # DreamHost & IBM
    templates.append("https://objects-us-east-1.dream.io/{}")
    templates.append("https://{}.s3.us.cloud-object-storage.appdomain.cloud")

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
    if shutdown_flag.is_set():
        return
    increment_counter()
    url = f"https://{name}.firebaseio.com/.json"
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False)
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
        if shutdown_flag.is_set():
            return
        increment_counter()
        try:
            r = requests.get(j_url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=False, verify=False)
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
        # Secrets & Credentials (PROVEN CRITICAL BOUNTY)
        ("/.env", "Environment File"),
        ("/.env.local", "Environment File"),
        ("/.env.bak", "Environment File"),
        ("/.aws/credentials", "AWS Credentials"),
        ("/.kube/config", "Kubernetes Config"),
        ("/.ssh/id_rsa", "SSH Private Key"),
        ("/.vscode/sftp.json", "VSCode SFTP Config"),
        ("/sftp-config.json", "SFTP Config"),
        ("/wp-config.php.bak", "WP Config Backup"),
        ("/docker-compose.yml", "Docker Compose"),
        ("/config/database.yml", "Rails DB Config"),
        # Source Code & Config (PROVEN HIGH BOUNTY)
        ("/.gitlab-ci.yml", "GitLab CI Config"),
        ("/composer.json", "Composer Config"),
        ("/package.json", "Node Package Config"),
        ("/.svn/entries", "SVN Repository"),
        # Swagger/OpenAPI (PROVEN MEDIUM BOUNTY)
        ("/v2/api-docs", "Swagger Docs"),
        ("/swagger.json", "Swagger Docs"),
        ("/swagger-ui.html", "Swagger UI"),
        ("/swagger-ui/", "Swagger UI"),
        ("/api-docs", "Swagger Docs"),
        # Debug & Status (PROVEN HIGH/CRITICAL BOUNTY)
        ("/console", "Werkzeug Debug Console (RCE)"),
        ("/phpinfo.php", "PHP Info"),
        ("/server-status", "Apache Server Status"),
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


def check_third_party(company, saas_perms):
    """Third-party checks using focused SaaS permutations ONLY."""
    safe_print(f"\n{GREEN}--- Third-Party Integrations (Targeted) ---{NC}")

    urls = []
    # High-value Subdomain-based SaaS
    for perm in saas_perms:
        urls.append((f"https://{perm}.zendesk.com", "Zendesk"))
        urls.append((f"https://{perm}.slack.com", "Slack Workspace"))
        urls.append((f"https://{perm}.atlassian.net", "Atlassian Cloud"))
        urls.append((f"https://{perm}.atlassian.net/wiki", "Confluence"))
        urls.append((f"https://sonar.{perm}.com", "SonarQube"))

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
        # Apache ActiveMQ (CRITICAL — RCE via PUT)
        (f"{base_url}:8161/admin/", "ActiveMQ Admin"),
        # Apache Storm (CRITICAL — RCE via Topology)
        (f"{base_url}:8080/api/v1/cluster/configuration", "Apache Storm UI"),
        # Prometheus (HIGH — internal metrics/secrets)
        (f"{base_url}:9090/", "Prometheus"),
        (f"{base_url}:9090/graph", "Prometheus"),
        (f"{base_url}:9090/api/v1/targets", "Prometheus Targets"),
        (f"https://prometheus.{domain}", "Prometheus"),
        # Kubernetes Dashboard (CRITICAL)
        (f"{base_url}:8443/", "Kubernetes Dashboard"),
        (f"{base_url}:10250/pods", "Kubelet API"),
        (f"{base_url}:10255/pods", "Kubelet Read-Only API (Unauth)"),
        (f"https://dashboard.{domain}", "Kubernetes Dashboard"),
        # cAdvisor (HIGH — container metrics)
        (f"{base_url}:4194/", "cAdvisor Node Metrics"),
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
        # Apache NiFi (CRITICAL — data flow RCE)
        (f"{base_url}:8080/nifi/", "Apache NiFi"),
        (f"{base_url}:8443/nifi/", "Apache NiFi HTTPS"),
        # Spring Boot Admin (HIGH — multi-app management)
        (f"{base_url}:8080/applications", "Spring Boot Admin"),
        (f"https://spring-admin.{domain}", "Spring Boot Admin"),
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
        # Spark (CRITICAL — job data / RCE via submit)
        (f"{base_url}:4040/", "Spark Jobs UI (Unauth)"),
        (f"{base_url}:8080/json/", "Spark Master UI (Unauth)"),
        (f"{base_url}:8081/", "Spark Worker UI (Unauth)"),
        (f"{base_url}:18080/", "Spark History Server"),
        # Couchbase (CRITICAL — full data access)
        (f"{base_url}:8091/", "Couchbase Console"),
        (f"{base_url}:8091/pools/default/buckets", "Couchbase Buckets"),
        # Redis direct (CRITICAL — if HTTP probe gets banner)
        (f"{base_url}:6379/", "Redis"),
        # Memcached (HIGH — cache data dump)
        (f"{base_url}:11211/", "Memcached"),
        # ArangoDB (CRITICAL — unauth DB access)
        (f"{base_url}:8529/", "ArangoDB Web UI"),
        # RethinkDB (CRITICAL — unauth DB access)
        (f"{base_url}:8080/#/", "RethinkDB Web UI"),
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


def check_saas_platforms(base_url, saas_perms):
    """Enterprise SaaS & IdP checks using focused SaaS permutations."""
    safe_print(f"\n{GREEN}--- Enterprise SaaS & IdP (Targeted) ---{NC}")

    checks = []
    checks.append((f"{base_url}/app/etc/local.xml", "Magento Config Leak"))

    for perm in saas_perms:
        checks.append((f"https://{perm}.service-now.com/kb_view.do", "ServiceNow KB"))
        checks.append((f"https://{perm}.service-now.com/sp_widget_list.do", "ServiceNow Widgets"))
        checks.append((f"https://{perm}.my.salesforce.com/aura", "Salesforce Lightning"))
        checks.append((f"https://auth.{perm}.com/auth/realms/master/.well-known/openid-configuration", "Keycloak Realm"))
        checks.append((f"https://{perm}.okta.com/.well-known/openid-configuration", "Okta Tenant"))
        checks.append((f"https://{perm}.auth0.com/.well-known/openid-configuration", "Auth0 Tenant"))

    safe_print(f"{CYAN}[*] Testing {len(checks)} SaaS URLs{NC}")
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(check_url, url, name): url for url, name in checks}
        concurrent.futures.wait(futures)


def check_idp_cms(base_url, saas_perms):
    """IdP and CMS Logic checks using focused SaaS permutations."""
    safe_print(f"\n{GREEN}--- IdP & CMS Logic (Targeted) ---{NC}")

    checks = []
    checks.append((f"{base_url}/wp-json/wp/v2/users", "WordPress Users"))
    checks.append((f"{base_url}/wp-admin/setup-config.php", "WordPress Setup"))
    checks.append((f"{base_url}/core/install.php", "Drupal Installer"))
    checks.append((f"{base_url}/user/register", "Drupal Registration"))

    for perm in saas_perms:
        checks.append((f"https://{perm}.okta.com/api/v1/users", "Okta API Users"))
        checks.append((f"https://auth.{perm}.com/auth/realms/master/account/", "Keycloak Registration"))

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(check_url, url, name): url for url, name in checks}
        concurrent.futures.wait(futures)


def check_intigriti_mapper(base_url, saas_perms):
    """Intigriti mapper with focused SaaS permutations."""
    safe_print(f"\n{GREEN}--- Intigriti Mapper Targets (Targeted) ---{NC}")

    checks = []
    checks.append((f"{base_url}/telescope/requests", "Laravel Telescope"))
    checks.append((f"{base_url}/jenkins/signup", "Jenkins Signup (Path)"))

    for perm in saas_perms:
        checks.append((f"https://{perm}.freshservice.com/support/signup", "Freshservice Signup"))
        checks.append((f"https://jenkins.{perm}.com/signup", "Jenkins Signup"))
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
    input_type is one of: 'url', 'domain', 'company', 'ip'
    """
    raw = raw.strip().rstrip("/")
    if not raw or raw.startswith("#"):
        return None, None, None, None

    # IP address (IPv4)
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", raw):
        return "ip", "ip-target", raw, f"https://{raw}"

    # URL
    if re.match(r"^https?://", raw):
        parsed = urlparse(raw)
        domain = parsed.hostname or ""
        base_url = f"{parsed.scheme}://{domain}"
        # Check if hostname is an IP
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
            return "ip", "ip-target", domain, base_url
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


def scan_single_target(input_type, domain, base_url, company, checks):
    """Scan a single domain/IP — runs all check categories in PARALLEL."""
    if shutdown_flag.is_set():
        return

    # --- For IP targets ---
    if input_type == "ip":
        ip = domain
        bases = [f"https://{ip}", f"http://{ip}"]
        tasks = []
        for scan_base in bases:
            if "web" in checks:
                tasks.extend([
                    lambda b=scan_base: check_app_vulns(b),
                    lambda b=scan_base: check_unique_vulns(b),
                    lambda b=scan_base: check_overlooked(b, ip),
                    lambda b=scan_base: check_ai_ml(b),
                ])
            if "ports" in checks:
                tasks.extend([
                    lambda b=scan_base: check_databases(b, ip),
                    lambda b=scan_base: check_infra_dashboards(b, ip),
                ])
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(tasks) or 1) as ex:
            list(ex.map(lambda fn: fn(), tasks))
        return

    # --- For domain/URL targets ---
    scan_base = base_url
    scan_domain = domain
    tasks = []

    if "web" in checks:
        tasks.extend([
            lambda: check_app_vulns(scan_base),
            lambda: check_unique_vulns(scan_base),
            lambda: check_jira(scan_base, company),
            lambda: check_overlooked(scan_base, scan_domain),
            lambda: check_ai_ml(scan_base),
        ])

    if "ports" in checks:
        tasks.extend([
            lambda: check_databases(scan_base, scan_domain),
            lambda: check_infra_dashboards(scan_base, scan_domain),
        ])

    if tasks:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(tasks)) as ex:
            list(ex.map(lambda fn: fn(), tasks))


def run_company_group(company, targets_in_group, permutations, checks):
    """
    Run a full scan for one company group.
    Bucket/SaaS run ONCE. Web/port run per unique subdomain.
    targets_in_group is a list of (input_type, domain, base_url).
    """
    safe_print(f"\n{CYAN}{'='*60}{NC}")
    safe_print(f"{CYAN} Company Group: {company}{NC}")
    safe_print(f"{CYAN} Subdomains/URLs: {len(targets_in_group)}{NC}")
    safe_print(f"{CYAN} Permutations: {len(permutations)}{NC}")
    safe_print(f"{CYAN} Checks: {', '.join(sorted(checks))}{NC}")
    safe_print(f"{CYAN}{'='*60}{NC}")

    # --- 1. Bucket + Firebase (ONCE per company) ---
    if "buckets" in checks:
        scan_cloud_buckets(permutations)
        safe_print(f"\n{GREEN}--- Firebase DB Check ---{NC}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = {executor.submit(check_firebase_db, perm): perm for perm in permutations}
            concurrent.futures.wait(futures)

    # --- 2. SaaS/IdP (ONCE per company) ---
    if "saas" in checks:
        # High-probability SaaS subdomains (avoid 500+ permutations for strict APIs)
        saas_perms = [
            company, f"{company}-dev", f"{company}-sandbox", f"{company}-qa",
            f"{company}-staging", f"{company}-sso", f"corp-{company}", 
            f"{company}-corp", f"dev-{company}", f"sso-{company}"
        ]
        
        first_base = targets_in_group[0][2] if targets_in_group else f"https://{company}.com"
        saas_tasks = [
            lambda: check_third_party(company, saas_perms),
            lambda: check_saas_platforms(first_base, saas_perms),
            lambda: check_idp_cms(first_base, saas_perms),
            lambda: check_intigriti_mapper(first_base, saas_perms),
        ]
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            list(ex.map(lambda fn: fn(), saas_tasks))

    # --- 3. Auto-TLD discovery for company-only entries ---
    expanded_targets = []
    for input_type, domain, base_url in targets_in_group:
        if input_type == "company":
            safe_print(f"\n{GREEN}--- Auto-TLD Discovery for '{company}' ---{NC}")
            tld_results = []

            def probe_tld(tld):
                test_domain = f"{company}{tld}"
                test_url = f"https://{test_domain}"
                try:
                    r = requests.head(test_url, headers=HEADERS,
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
                    expanded_targets.append(("domain", d, u))
                safe_print(f"{CYAN}[+] Found {len(tld_results)} live TLD(s){NC}")
            else:
                fallback = f"{company}.com"
                expanded_targets.append(("domain", fallback, f"https://{fallback}"))
                safe_print(f"{YELLOW}[!] No live TLDs found, falling back to {fallback}{NC}")
        else:
            expanded_targets.append((input_type, domain, base_url))

    # --- 4. Dedup and run web/port per unique subdomain ---
    seen_domains = set()
    unique_targets = []
    for t in expanded_targets:
        key = t[1]  # domain or IP
        if key not in seen_domains:
            seen_domains.add(key)
            unique_targets.append(t)

    safe_print(f"\n{CYAN}[+] Probing {len(unique_targets)} unique host(s) for {company}...{NC}")

    # --- Phase 1: Fast liveness probe (all hosts in parallel) ---
    live_targets = []

    def _probe(args):
        itype, dom, burl = args
        if shutdown_flag.is_set():
            return None
        is_live = probe_host(burl)
        # Update progress on every probe
        with counter_lock:
            total = hosts_probed
        if total % 50 == 0:
            elapsed = time.time() - scan_start_time if scan_start_time else 0
            sys.stderr.write(f"\r\033[K\033[36m[PROBE] {total}/{len(unique_targets)} probed | {hosts_alive} live | {hosts_dead} dead | {elapsed:.0f}s\033[0m")
            sys.stderr.flush()
        if is_live:
            record_live_host(dom)
            return (itype, dom, burl)
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=HOST_PARALLEL * 5) as ex:
        results = list(ex.map(_probe, unique_targets))

    live_targets = [r for r in results if r is not None]
    sys.stderr.write("\r\033[K")  # Clear probe line
    safe_print(f"{GREEN}[+] Liveness: {hosts_alive} alive / {hosts_dead} dead out of {len(unique_targets)} hosts{NC}")

    if not live_targets:
        safe_print(f"{YELLOW}[!] No live hosts found for {company} — skipping detailed checks{NC}")
        return

    # --- Phase 2: Run heavy checks only against live hosts ---
    safe_print(f"{CYAN}[+] Running checks on {len(live_targets)} live host(s) ({HOST_PARALLEL} in parallel){NC}")

    def _scan_host(args):
        i, (itype, dom, burl) = args
        if shutdown_flag.is_set():
            return
        safe_print(f"{CYAN}  [{i}/{len(live_targets)}] {dom}{NC}")
        scan_single_target(itype, dom, burl, company, checks)

    with concurrent.futures.ThreadPoolExecutor(max_workers=HOST_PARALLEL) as ex:
        list(ex.map(_scan_host, enumerate(live_targets, 1)))


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
    BAN = f"""{CYAN}
    ██████╗ ██╗   ██╗ ██████╗██╗  ██╗
    ██╔══██╗██║   ██║██╔════╝██║ ██╔╝
    ██████╔╝██║   ██║██║     █████╔╝ 
    ██╔══██╗██║   ██║██║     ██╔═██╗ 
    ██████╔╝╚██████╔╝╚██████╗██║  ██╗
    ╚═════╝  ╚═════╝  ╚═════╝╚═╝  ╚═╝
                {RED}Scanner v3.0{NC}
"""
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False,
        description=f"{BAN}\n{GREEN} Enhanced Cloud Bucket & Misconfiguration Scanner{NC}\n{YELLOW} ================================================================={NC}",
        epilog=f"""
{CYAN}TARGET FLAGS (Required - pick one):{NC}
  {GREEN}-org <target>{NC}         Scan org (auto-TLD + permutations)
  {GREEN}-list <file>{NC}          Batch scan from file (one target per line)

{CYAN}CHECK CATEGORIES (Optional - pick one or more):{NC}
  {GREEN}-p{NC}                    Port-based checks only (DB panels, infra dashboards)
  {GREEN}-b{NC}                    Cloud bucket + Firebase checks only
  {GREEN}-w{NC}                    Web app vulnerability checks only (git, env, swagger)
  {GREEN}-s{NC}                    SaaS & third-party integration checks only
  
  {YELLOW}* If NO category flag is given, ALL checks run by default.{NC}

{CYAN}GENERAL OPTIONS:{NC}
  {GREEN}-o <prefix>{NC}           Output file prefix (default: auto-generated)
  {GREEN}-h, --help{NC}            Show this beautiful help message and exit

{CYAN}SMART GROUPING:{NC}
  Targets auto-grouped by root company. Bucket/SaaS run ONCE per company.
  Web/port checks run per unique subdomain. Duplicates are skipped.
  e.g. {YELLOW}dev.walmart.com + api.walmart.com = 1 bucket scan, 2 web scans.{NC}

{CYAN}EXAMPLES:{NC}
  {GREEN}python buck.py -org uber{NC}                 Run ALL checks on uber
  {GREEN}python buck.py -org uber -p{NC}              Port scan only
  {GREEN}python buck.py -list subs.txt{NC}            Smart grouped full scan
  {GREEN}python buck.py -list subs.txt -p{NC}         Ports only, grouped
"""
    )
    
    parser.add_argument("-org", dest="org", help=argparse.SUPPRESS)
    parser.add_argument("-list", dest="listfile", help=argparse.SUPPRESS)
    parser.add_argument("-p", dest="ports", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("-b", dest="buckets", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("-w", dest="web", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("-s", dest="saas", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("-o", dest="output", default=None, help=argparse.SUPPRESS)
    parser.add_argument("-h", "--help", action="help", default=argparse.SUPPRESS, help=argparse.SUPPRESS)

    # Backward compat positional
    parser.add_argument("target", nargs="?", help=argparse.SUPPRESS)

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

    # Determine raw targets
    raw_targets = []
    if args.listfile:
        if not os.path.isfile(args.listfile):
            print(f"{RED}[!] File not found: {args.listfile}{NC}")
            sys.exit(1)
        with open(args.listfile, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    raw_targets.append(line)
        if not raw_targets:
            print(f"{RED}[!] No targets found in {args.listfile}{NC}")
            sys.exit(1)
        safe_print(f"{CYAN}[+] Loaded {len(raw_targets)} target(s) from {args.listfile}{NC}")
    elif args.org:
        raw_targets.append(args.org)
    elif args.target:
        raw_targets.append(args.target)
    else:
        parser.print_help()
        sys.exit(1)

    # --- Initialize output files ---
    global OUTPUT_LIVE_FILE, OUTPUT_PORTS_FILE, OUTPUT_FINDINGS_FILE
    if args.output:
        prefix = args.output
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        prefix = f"scan_{ts}"

    OUTPUT_LIVE_FILE = f"{prefix}_live.txt"
    OUTPUT_PORTS_FILE = f"{prefix}_ports.txt"
    OUTPUT_FINDINGS_FILE = f"{prefix}_findings.txt"

    for fp in [OUTPUT_LIVE_FILE, OUTPUT_PORTS_FILE, OUTPUT_FINDINGS_FILE]:
        with open(fp, "w", encoding="utf-8") as f:
            f.write(f"# Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    # --- Classify and group targets by company ---
    from collections import OrderedDict
    company_groups = OrderedDict()
    ip_targets = []
    seen_raw = set()

    for raw in raw_targets:
        raw_lower = raw.strip().lower()
        if raw_lower in seen_raw:
            continue
        seen_raw.add(raw_lower)

        input_type, company, domain, base_url = classify_input(raw)
        if input_type is None:
            continue

        if input_type == "ip":
            ip_targets.append((domain, base_url))
        else:
            if company not in company_groups:
                company_groups[company] = []
            company_groups[company].append((input_type, domain, base_url))

    # --- Banner ---
    safe_print(f"\n{CYAN}{'='*60}{NC}")
    safe_print(f"{CYAN}  Enhanced Bucket & Misconfig Scanner v3.0{NC}")
    safe_print(f"{CYAN}  Total inputs: {len(raw_targets)} | Unique: {len(seen_raw)}{NC}")
    safe_print(f"{CYAN}  Company groups: {len(company_groups)}{NC}")
    if ip_targets:
        safe_print(f"{CYAN}  IP targets: {len(ip_targets)}{NC}")
    safe_print(f"{CYAN}  Threads: {MAX_THREADS} | Checks: {', '.join(sorted(checks)).upper()}{NC}")
    safe_print(f"{CYAN}  Output: {prefix}_*.txt{NC}")
    safe_print(f"{CYAN}{'='*60}{NC}")

    # Show grouping preview
    for comp, tgts in company_groups.items():
        safe_print(f"{GREEN}  [{comp}] -> {len(tgts)} target(s){NC}")
    if ip_targets:
        safe_print(f"{GREEN}  [IPs] -> {len(ip_targets)} target(s){NC}")

    # --- Start timer ---
    global scan_start_time
    scan_start_time = time.time()

    # --- Run per company group ---
    for idx, (company, targets_in_group) in enumerate(company_groups.items(), 1):
        safe_print(f"\n{CYAN}{'#'*60}{NC}")
        safe_print(f"{CYAN}# COMPANY [{idx}/{len(company_groups)}]: {company} ({len(targets_in_group)} targets){NC}")
        safe_print(f"{CYAN}{'#'*60}{NC}")

        permutations = generate_permutations(company)
        safe_print(f"{CYAN}[+] Generated {len(permutations)} permutations for '{company}'{NC}")

        run_company_group(company, targets_in_group, permutations, checks)

    # --- Run IP targets ---
    if ip_targets:
        safe_print(f"\n{CYAN}{'#'*60}{NC}")
        safe_print(f"{CYAN}# IP TARGETS: {len(ip_targets)} IPs{NC}")
        safe_print(f"{CYAN}{'#'*60}{NC}")

        if "buckets" in checks:
            safe_print(f"{YELLOW}[!] Bucket checks skipped for IP targets{NC}")
        if "saas" in checks:
            safe_print(f"{YELLOW}[!] SaaS checks skipped for IP targets{NC}")

        def _scan_ip(args):
            i, (ip, burl) = args
            if shutdown_flag.is_set():
                return
            safe_print(f"{CYAN}  IP [{i}/{len(ip_targets)}]: {ip}{NC}")
            scan_single_target("ip", ip, burl, "ip-target", checks)

        with concurrent.futures.ThreadPoolExecutor(max_workers=HOST_PARALLEL) as ex:
            list(ex.map(_scan_ip, enumerate(ip_targets, 1)))

    # Final Summary
    sys.stderr.write("\r\033[K")  # Clear progress line
    elapsed = time.time() - scan_start_time if scan_start_time else 0
    if elapsed > 0:
        safe_print(f"\n{CYAN}[+] Scan completed in {elapsed:.1f}s{NC}")
        safe_print(f"{CYAN}    Hosts probed: {hosts_probed} ({hosts_alive} alive, {hosts_dead} dead){NC}")
        safe_print(f"{CYAN}    Requests sent: {request_counter} ({request_counter/elapsed:.0f} req/s){NC}")
    print_summary()

    # Output file stats
    safe_print(f"\n{CYAN}{'='*60}{NC}")
    safe_print(f"{CYAN}  Output Files:{NC}")
    safe_print(f"{CYAN}  Live hosts:  {OUTPUT_LIVE_FILE} ({len(seen_live_hosts)} hosts){NC}")
    safe_print(f"{CYAN}  Live ports:  {OUTPUT_PORTS_FILE} ({len(seen_live_ports)} ports){NC}")
    safe_print(f"{CYAN}  Findings:    {OUTPUT_FINDINGS_FILE} ({len(findings)} findings){NC}")
    safe_print(f"{CYAN}{'='*60}{NC}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.stderr.write("\r\033[K")
        shutdown_flag.set()
        elapsed = time.time() - scan_start_time if scan_start_time else 0
        print(f"\n{YELLOW}[!] Scan interrupted by user after {request_counter} requests ({elapsed:.1f}s){NC}")
        print(f"{CYAN}  Partial results saved to output files.{NC}")
        sys.exit(0)
