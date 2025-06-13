import requests
import yaml
import json
import re
import sqlite3
import hashlib
from datetime import datetime
import time
import os
import uuid
import traceback
import sys

# --- Global Configuration ---
CONFIG_FILE = 'config.json'
DB_FILE = 'sigma_rules.db'
RULES_DIR = 'sigma_rules_files'
REQUEST_TIMEOUT = 30
USER_AGENT = "SigmaRuleCollector/1.0"

def get_elapsed_time_str(start_time_seconds: float) -> str:
    """Converts elapsed seconds since start_time_seconds to a HH:MM:SS string."""
    elapsed_total_seconds = int(time.time() - start_time_seconds)
    hours, remainder = divmod(elapsed_total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

def normalize_title(title: str) -> str:
    """
    Normalizes a rule title by stripping whitespace and converting to lowercase.
    Returns an empty string if the title is None.
    """
    if not title:
        return ""
    return title.strip().lower()

def init_db(overall_start_time: float):
    """
    Initializes the SQLite database and creates the sigma_rules table if it doesn't exist.
    """
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS sigma_rules (
            id TEXT PRIMARY KEY, title TEXT, status TEXT, description TEXT, author TEXT,
            "references" TEXT, logsource_category TEXT, logsource_product TEXT, detection TEXT,
            falsepositives TEXT, level TEXT, tags TEXT, raw_rule TEXT, source_name TEXT,
            source_url TEXT, first_seen_at TIMESTAMP, last_updated_at TIMESTAMP, rule_hash TEXT
        )''')
        conn.commit()
        print(f"[{get_elapsed_time_str(overall_start_time)}] Database initialized successfully.")
    except Exception as e:
        print(f"[{get_elapsed_time_str(overall_start_time)}] Critical error during DB initialization: {e}. Exiting.")
        raise
    finally:
        if conn:
            conn.close()

def store_rule(parsed_rule_data: dict, raw_rule_content: str, source_name: str, source_url: str, live_status: dict, overall_start_time: float):
    """
    Stores a single parsed Sigma rule into the database and as a YAML file.
    Handles rule updates, versioning, and duplicate checks.
    """
    conn = None
    rule_processed_for_stats = True
    new_rule_title_from_file = parsed_rule_data.get('title', 'Untitled Rule').strip()

    db_status_text = "DB Unchanged"
    file_status_text = "File N/A"
    filename_for_saving = "ErrorInFilenameGeneration.yml"

    LOG_RULE_TITLE_LEN = 65
    LOG_SOURCE_NAME_LEN = 22
    LOG_FILENAME_DISPLAY_LEN = 35

    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        current_time = datetime.now()

        if not os.path.exists(RULES_DIR):
            try:
                os.makedirs(RULES_DIR)
            except OSError:
                pass 

        new_rule_id_from_file = parsed_rule_data.get('id')
        if new_rule_id_from_file is not None:
            new_rule_id_from_file = str(new_rule_id_from_file)

        new_rule_detection_dict = parsed_rule_data.get('detection', {})
        new_rule_hash = hashlib.sha256(raw_rule_content.encode('utf-8')).hexdigest()

        if not new_rule_id_from_file:
            title_slug = re.sub(r'\W+', '_', new_rule_title_from_file.lower() if new_rule_title_from_file else 'untitled')
            new_rule_id_from_file = f"gen_{title_slug[:50]}_{new_rule_hash[:8]}"

        if not new_rule_title_from_file or new_rule_title_from_file == 'Untitled Rule':
            db_status_text = "Skipped (no title)"
            file_status_text = "File Skipped"
            print(f"[{get_elapsed_time_str(overall_start_time)}] '{new_rule_title_from_file[:LOG_RULE_TITLE_LEN]}' ({source_name[:LOG_SOURCE_NAME_LEN]}): {db_status_text}")
            live_status["session_rules_skipped_no_title"] = live_status.get("session_rules_skipped_no_title", 0) + 1
            rule_processed_for_stats = False
            return

        cleaned_title_for_filename = re.sub(r'[^\w\._-]+', '_', new_rule_title_from_file)
        filename_for_saving = f"{cleaned_title_for_filename[:100]}_{new_rule_hash[:8]}.yml"

        try:
            if not os.path.exists(RULES_DIR):
                file_status_text = "File Error (Dir missing)"
            else:
                filepath = os.path.join(RULES_DIR, filename_for_saving)
                with open(filepath, 'w', encoding='utf-8') as f_rule:
                    f_rule.write(raw_rule_content)
                file_status_text = f"File OK: '{filename_for_saving}'"
        except Exception as e_file:
            file_status_text = f"File Error: {str(e_file)[:75]}"

        cursor.execute("SELECT * FROM sigma_rules WHERE id = ?", (new_rule_id_from_file,))
        db_rule_by_id = cursor.fetchone()

        if db_rule_by_id:
            if db_rule_by_id['rule_hash'] == new_rule_hash:
                cursor.execute("UPDATE sigma_rules SET last_updated_at = ?, source_name = ?, source_url = ? WHERE id = ?",
                               (current_time, source_name, source_url, new_rule_id_from_file))
                db_status_text = "DB TS \u2705"
                live_status["session_rules_updated_ts"] = live_status.get("session_rules_updated_ts", 0) + 1
            else:
                logsource = parsed_rule_data.get('logsource', {})
                detection = parsed_rule_data.get('detection', {})
                cursor.execute("UPDATE sigma_rules SET title=?, status=?, description=?, author=?, \"references\"=?, logsource_category=?, logsource_product=?, detection=?, falsepositives=?, level=?, tags=?, raw_rule=?, source_name=?, source_url=?, last_updated_at=?, rule_hash=? WHERE id=?",
                               (new_rule_title_from_file, parsed_rule_data.get('status'), parsed_rule_data.get('description'), parsed_rule_data.get('author'), json.dumps(parsed_rule_data.get('references', [])), logsource.get('category'), logsource.get('product'), json.dumps(detection), json.dumps(parsed_rule_data.get('falsepositives', [])), parsed_rule_data.get('level'), json.dumps(parsed_rule_data.get('tags', [])), raw_rule_content, source_name, source_url, current_time, new_rule_hash, new_rule_id_from_file))
                db_status_text = "DB Content Updated"
                live_status["session_rules_updated_content"] = live_status.get("session_rules_updated_content", 0) + 1
        else:
            base_title_new = normalize_title(re.sub(r"\s*v\d+(\.\d+)*$", "", new_rule_title_from_file, flags=re.IGNORECASE).strip())
            cursor.execute("SELECT id, title, rule_hash, detection, first_seen_at FROM sigma_rules")
            all_db_rules = cursor.fetchall()
            title_family_rules_db = []
            for row in all_db_rules:
                db_title_stripped = normalize_title(re.sub(r"\s*v\d+(\.\d+)*$", "", row['title'], flags=re.IGNORECASE).strip())
                if db_title_stripped == base_title_new:
                    try:
                        dt_str = row['first_seen_at'].split('.')[0]
                        first_seen_dt = datetime.fromisoformat(dt_str)
                    except:
                        first_seen_dt = datetime.min
                    title_family_rules_db.append({**dict(row), 'first_seen_at_dt': first_seen_dt})
            
            if not title_family_rules_db:
                logsource = parsed_rule_data.get('logsource', {})
                detection = parsed_rule_data.get('detection', {})
                cursor.execute("INSERT INTO sigma_rules VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                               (new_rule_id_from_file, new_rule_title_from_file, parsed_rule_data.get('status'), parsed_rule_data.get('description'), parsed_rule_data.get('author'), json.dumps(parsed_rule_data.get('references', [])), logsource.get('category'), logsource.get('product'), json.dumps(detection), json.dumps(parsed_rule_data.get('falsepositives', [])), parsed_rule_data.get('level'), json.dumps(parsed_rule_data.get('tags', [])), raw_rule_content, source_name, source_url, current_time, current_time, new_rule_hash))
                db_status_text = "DB New"
                live_status["session_rules_added_new"] = live_status.get("session_rules_added_new", 0) + 1
            else:
                title_family_rules_db.sort(key=lambda r: r['first_seen_at_dt'])
                primary_rule = title_family_rules_db[0]
                hash_match_in_family = any(r['rule_hash'] == new_rule_hash for r in title_family_rules_db)

                if hash_match_in_family:
                    matched_rule_id_obj = next(r['id'] for r in title_family_rules_db if r['rule_hash'] == new_rule_hash)
                    cursor.execute("UPDATE sigma_rules SET last_updated_at=?, source_name=?, source_url=? WHERE id=?", (current_time, source_name, source_url, str(matched_rule_id_obj)))
                    db_status_text = "DB TS \u2705 (Family)"
                    live_status["session_rules_updated_ts"] = live_status.get("session_rules_updated_ts", 0) + 1
                else:
                    try:
                        primary_detection_dict = json.loads(primary_rule['detection'])
                    except (json.JSONDecodeError, TypeError):
                        primary_detection_dict = {}

                    if new_rule_detection_dict == primary_detection_dict:
                        cursor.execute("UPDATE sigma_rules SET last_updated_at=?, source_name=?, source_url=? WHERE id=?", (current_time, source_name, source_url, str(primary_rule['id'])))
                        db_status_text = "DB TS \u2705 (Detection)"
                        live_status["session_rules_updated_ts"] = live_status.get("session_rules_updated_ts", 0) + 1
                    else:
                        base_title_versioning = re.sub(r"\s*v\d+(\.\d+)*$", "", primary_rule['title'], flags=re.IGNORECASE).strip()
                        max_v = 0
                        for r_v in title_family_rules_db:
                            m = re.match(rf"^{re.escape(base_title_versioning)}\s*v(\d+)", r_v['title'], re.IGNORECASE)
                            if m: max_v = max(max_v, int(m.group(1)))
                        if max_v == 0 and normalize_title(primary_rule['title']) == normalize_title(base_title_versioning): max_v = 1
                        
                        versioned_title = f"{base_title_versioning} v{max_v + 1}"
                        logsource = parsed_rule_data.get('logsource', {})
                        detection = parsed_rule_data.get('detection', {})
                        cursor.execute("INSERT INTO sigma_rules VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                                       (new_rule_id_from_file, versioned_title, parsed_rule_data.get('status'), parsed_rule_data.get('description'), parsed_rule_data.get('author'), json.dumps(parsed_rule_data.get('references', [])), logsource.get('category'), logsource.get('product'), json.dumps(detection), json.dumps(parsed_rule_data.get('falsepositives', [])), parsed_rule_data.get('level'), json.dumps(parsed_rule_data.get('tags', [])), raw_rule_content, source_name, source_url, current_time, current_time, new_rule_hash))
                        db_status_text = f"DB New Version '{versioned_title}'"
                        live_status["session_rules_added_version"] = live_status.get("session_rules_added_version", 0) + 1
        
        conn.commit()

        log_display_filename = filename_for_saving
        if len(filename_for_saving) > LOG_FILENAME_DISPLAY_LEN:
            log_display_filename = filename_for_saving[:LOG_FILENAME_DISPLAY_LEN-3] + "..."
        
        current_file_status_for_log = file_status_text
        if file_status_text.startswith("File OK:"):
             current_file_status_for_log = f"File OK: '{log_display_filename}'"

        print(
            f"[{get_elapsed_time_str(overall_start_time)}] "
            f"'{new_rule_title_from_file[:LOG_RULE_TITLE_LEN]}' "
            f"({source_name[:LOG_SOURCE_NAME_LEN]}): "
            f"{db_status_text} - "
            f"{current_file_status_for_log}"
        )

    except sqlite3.Error as e_sql:
        db_status_text = f"DB-Error: {str(e_sql)[:100]}"
        print(
            f"[{get_elapsed_time_str(overall_start_time)}] "
            f"'{new_rule_title_from_file[:LOG_RULE_TITLE_LEN]}' "
            f"({source_name[:LOG_SOURCE_NAME_LEN]}): "
            f"{db_status_text} - "
            f"{file_status_text}"
        )
        rule_processed_for_stats = False
    except Exception as e_gen:
        db_status_text = f"General Error: {str(e_gen)[:100]}"
        print(
            f"[{get_elapsed_time_str(overall_start_time)}] "
            f"'{new_rule_title_from_file[:LOG_RULE_TITLE_LEN]}' "
            f"({source_name[:LOG_SOURCE_NAME_LEN]}): "
            f"{db_status_text} - "
            f"{file_status_text}"
        )
        rule_processed_for_stats = False
    finally:
        if conn:
            conn.close()
        if rule_processed_for_stats:
            live_status["session_rules_processed"] = live_status.get("session_rules_processed", 0) + 1
        elif not (db_status_text == "Skipped (no title)"):
            live_status["session_rules_skipped_other"] = live_status.get("session_rules_skipped_other", 0) + 1
    
    time.sleep(0.005)

def fetch_url_content(url: str, headers: dict, source_name: str, overall_start_time: float, proxies: dict = None) -> str | None:
    """
    Fetches content from a given URL, optionally via a proxy. 
    Returns content as text or None on error.
    """
    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers, proxies=proxies)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"[{get_elapsed_time_str(overall_start_time)}]   Network error for {source_name} (URL: ...{url[-90:]}): {str(e)[:150]}")
        return None
    except Exception as e_gen:
        print(f"[{get_elapsed_time_str(overall_start_time)}]   Unexpected download error for {source_name} (URL: ...{url[-90:]}): {str(e_gen)[:150]}")
        return None

def fetch_and_process_github_directory(api_dir_url: str, source_config_name: str, base_request_headers: dict, live_status: dict, overall_start_time: float, proxies: dict = None):
    """
    Recursively fetches and processes rules from a GitHub repository folder.
    """
    directory_content_text = fetch_url_content(api_dir_url, base_request_headers, source_config_name, overall_start_time, proxies)
    if not directory_content_text:
        return

    try:
        items = json.loads(directory_content_text)
        if not isinstance(items, list):
            if isinstance(items, dict) and items.get('type') == 'file':
                items = [items]
            elif isinstance(items, dict) and 'message' in items:
                print(f"[{get_elapsed_time_str(overall_start_time)}]   GitHub API Error in {source_config_name} (...{api_dir_url[-75:]}): {items.get('message')[:150]}")
                return
            else:
                print(f"[{get_elapsed_time_str(overall_start_time)}]   Unexpected GitHub API response for {source_config_name} (...{api_dir_url[-75:]})")
                return

        for item in items:
            item_path = item.get('path', item.get('name', 'unknown_item'))
            is_yaml_file = item.get('type') == 'file' and item.get('name', '').endswith(('.yml', '.yaml'))

            if is_yaml_file:
                file_download_url = item.get('download_url')
                if not file_download_url:
                    print(f"[{get_elapsed_time_str(overall_start_time)}]   No download URL for '{item_path[:90]}' in {source_config_name}.")
                    live_status["session_rules_skipped_other"] = live_status.get("session_rules_skipped_other", 0) + 1
                    live_status["session_rules_processed"] += 1
                    continue

                file_content = fetch_url_content(file_download_url, base_request_headers, source_config_name, overall_start_time, proxies)
                if file_content:
                    try:
                        cleaned_content = file_content.replace('\xa0', ' ').replace('\ufeff', '')
                        rule_data = yaml.safe_load(cleaned_content)
                        if isinstance(rule_data, dict) and rule_data.get('title'):
                            store_rule(rule_data, cleaned_content, source_config_name, file_download_url, live_status, overall_start_time)
                        else:
                            print(f"[{get_elapsed_time_str(overall_start_time)}]   Defective rule '{item_path[:90]}' ({source_config_name}): Invalid content or no title.")
                            live_status["session_rules_skipped_defective"] = live_status.get("session_rules_skipped_defective", 0) + 1
                            live_status["session_rules_processed"] += 1
                    except yaml.YAMLError as e_yaml:
                        error_message = str(e_yaml).replace('\n', ' ').replace('\r', '')
                        print(f"[{get_elapsed_time_str(overall_start_time)}]   Defective rule '{item_path[:90]}' ({source_config_name}): Invalid YAML. Error: {error_message[:150]}")
                        live_status["session_rules_skipped_defective"] = live_status.get("session_rules_skipped_defective", 0) + 1
                        live_status["session_rules_processed"] += 1
                else:
                    live_status["session_rules_skipped_other"] = live_status.get("session_rules_skipped_other", 0) + 1
                    live_status["session_rules_processed"] += 1
            elif item.get('type') == 'dir':
                dir_api_url = item.get('url')
                if dir_api_url:
                    fetch_and_process_github_directory(dir_api_url, source_config_name, base_request_headers, live_status, overall_start_time, proxies)
            time.sleep(0.005)
    except json.JSONDecodeError as e_json:
        print(f"[{get_elapsed_time_str(overall_start_time)}]   JSON Error for directory {source_config_name} (...{api_dir_url[-75:]}): {str(e_json)[:150]}")
    except Exception as e_outer:
        print(f"[{get_elapsed_time_str(overall_start_time)}]   General Error for directory {source_config_name} (...{api_dir_url[-75:]}): {str(e_outer)[:150]}")

def process_source(source_config: dict, live_status: dict, overall_start_time: float, proxies: dict = None):
    """
    Processes a single source from the configuration file based on its type.
    """
    source_name = source_config['name']
    source_url = source_config['url']
    print(f"[{get_elapsed_time_str(overall_start_time)}] Processing Source: {source_name} (URL: {source_url[:105]}...)")
    request_headers = {'User-Agent': USER_AGENT}

    source_type = source_config.get('type')

    if source_type == 'github_repo_folder':
        github_headers = {'User-Agent': USER_AGENT, 'Accept': 'application/vnd.github.v3+json'}
        if source_config.get('github_token'):
            github_headers['Authorization'] = f"token {source_config['github_token']}"
        fetch_and_process_github_directory(source_url, source_name, github_headers, live_status, overall_start_time, proxies)

    elif source_type == 'single_file_yaml':
        content = fetch_url_content(source_url, request_headers, source_name, overall_start_time, proxies)
        if content:
            try:
                cleaned_content = content.replace('\xa0', ' ').replace('\ufeff', '')
                rule_data = yaml.safe_load(cleaned_content)
                if isinstance(rule_data, dict) and rule_data.get('title'):
                    store_rule(rule_data, cleaned_content, source_name, source_url, live_status, overall_start_time)
                else:
                    print(f"[{get_elapsed_time_str(overall_start_time)}]   Defective rule (single file) '{source_name[:75]}': Invalid content or no title.")
                    live_status["session_rules_skipped_defective"] = live_status.get("session_rules_skipped_defective", 0) + 1
                    live_status["session_rules_processed"] += 1
            except yaml.YAMLError as e_yaml:
                error_message = str(e_yaml).replace('\n', ' ').replace('\r', '')
                print(f"[{get_elapsed_time_str(overall_start_time)}]   Defective rule (single file) '{source_name[:75]}': Invalid YAML. Error: {error_message[:150]}")
                live_status["session_rules_skipped_defective"] = live_status.get("session_rules_skipped_defective", 0) + 1
                live_status["session_rules_processed"] += 1
            except Exception as e_single:
                print(f"[{get_elapsed_time_str(overall_start_time)}]   Error processing single file '{source_name[:75]}': {str(e_single)[:150]}")
                live_status["session_rules_skipped_other"] = live_status.get("session_rules_skipped_other", 0) + 1
                live_status["session_rules_processed"] += 1
        else:
            live_status["session_rules_skipped_other"] = live_status.get("session_rules_skipped_other", 0) + 1
            live_status["session_rules_processed"] += 1
            
    elif source_type == 'raw_text_regex':
        content = fetch_url_content(source_url, request_headers, source_name, overall_start_time, proxies)
        if content:
            rule_pattern = re.compile(source_config.get('rule_regex', r"(?sm)(^title:.*?)(?=^title:|\Z)"))
            matches = list(rule_pattern.finditer(content))
            print(f"[{get_elapsed_time_str(overall_start_time)}]   Found {len(matches)} regex matches in '{source_name}'.")
            for i, match in enumerate(matches):
                raw_rule_segment = match.group(1).strip()
                try:
                    cleaned_segment = raw_rule_segment.replace('\xa0', ' ').replace('\ufeff', '')
                    rule_data = yaml.safe_load(cleaned_segment)
                    if isinstance(rule_data, dict) and rule_data.get('title'):
                        store_rule(rule_data, cleaned_segment, source_name, f"{source_url} (Match {i+1})", live_status, overall_start_time)
                    else:
                        print(f"[{get_elapsed_time_str(overall_start_time)}]   Defective rule (Regex Match {i+1}, {source_name[:60]}): Invalid content or no title.")
                        live_status["session_rules_skipped_defective"] = live_status.get("session_rules_skipped_defective", 0) + 1
                        live_status["session_rules_processed"] += 1
                except yaml.YAMLError as e_yaml:
                    error_message = str(e_yaml).replace('\n', ' ').replace('\r', '')
                    print(f"[{get_elapsed_time_str(overall_start_time)}]   Defective rule (Regex Match {i+1}, {source_name[:60]}): Invalid YAML. Error: {error_message[:150]}")
                    live_status["session_rules_skipped_defective"] = live_status.get("session_rules_skipped_defective", 0) + 1
                    live_status["session_rules_processed"] += 1
                except Exception as e_regex:
                    print(f"[{get_elapsed_time_str(overall_start_time)}]   Error processing regex match {i+1} ({source_name[:60]}): {str(e_regex)[:150]}")
                    live_status["session_rules_skipped_other"] = live_status.get("session_rules_skipped_other", 0) + 1
                    live_status["session_rules_processed"] += 1
        else:
            live_status["session_rules_skipped_other"] = live_status.get("session_rules_skipped_other", 0) + 1
            live_status["session_rules_processed"] += 1
    else:
        print(f"[{get_elapsed_time_str(overall_start_time)}]   Unknown source type: '{source_type}' for source '{source_name}'.")

    print(f"[{get_elapsed_time_str(overall_start_time)}] Source '{source_name}' completed.")

def main():
    """
    Main entry point for the script. Handles configuration, initializes the database,
    processes all enabled sources, and prints final statistics.
    """
    proxies = {
        'http': os.environ.get('HTTP_PROXY'),
        'https': os.environ.get('HTTPS_PROXY')
    }
    # Filter out None values so we don't pass empty proxy entries to requests
    proxies = {key: value for key, value in proxies.items() if value}
    
    if proxies:
        print(f"Using system proxies: {list(proxies.keys())}")

    print("--- Sigma Rule Collector ---")
    print("Starting collection process...")

    overall_start_time = time.time()
    live_status = {
        "session_rules_processed": 0, "session_rules_added_new": 0,
        "session_rules_updated_content": 0, "session_rules_updated_ts": 0,
        "session_rules_added_version": 0, "session_rules_skipped_no_title": 0,
        "session_rules_skipped_other": 0, "session_rules_skipped_defective": 0
    }

    try:
        init_db(overall_start_time)

        if not os.path.exists(CONFIG_FILE):
            print(f"[{get_elapsed_time_str(overall_start_time)}] Config file '{CONFIG_FILE}' not found.")
            example_config = [
                {
                    "name": "SigmaHQ Windows (Example)",
                    "url": "https://api.github.com/repos/SigmaHQ/sigma/contents/rules/windows",
                    "type": "github_repo_folder",
                    "github_token": "",
                    "enabled": True
                },
                {
                    "name": "Single Rule (Example)",
                    "url": "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_lolbas_forfiles.yml",
                    "type": "single_file_yaml",
                    "enabled": True
                }
            ]
            try:
                with open(CONFIG_FILE, 'w', encoding='utf-8') as f_cfg:
                    json.dump(example_config, f_cfg, indent=4)
                print(f"[{get_elapsed_time_str(overall_start_time)}] Example config '{CONFIG_FILE}' created. Please adapt and restart.")
            except IOError as e_io:
                print(f"[{get_elapsed_time_str(overall_start_time)}] Error creating example config: {e_io}")
            return

        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
        except json.JSONDecodeError as e_json_cfg:
            print(f"[{get_elapsed_time_str(overall_start_time)}] Error parsing config file '{CONFIG_FILE}': {e_json_cfg}. Please check syntax.")
            return

        enabled_sources = [s for s in config_data if s.get("enabled", False)]
        disabled_source_names = [s.get('name', 'Unnamed') for s in config_data if not s.get("enabled", False)]

        if not enabled_sources:
            print(f"[{get_elapsed_time_str(overall_start_time)}] No active sources configured. Exiting.")
        else:
            print(f"[{get_elapsed_time_str(overall_start_time)}] Found {len(enabled_sources)} active sources.")
            for i, source_cfg in enumerate(enabled_sources):
                print(f"\n[{get_elapsed_time_str(overall_start_time)}] --- Starting Source {i+1}/{len(enabled_sources)} ---")
                process_source(source_cfg, live_status, overall_start_time, proxies=proxies)
                print(f"[{get_elapsed_time_str(overall_start_time)}] --- Finished Source {i+1}/{len(enabled_sources)} ---")

        if disabled_source_names:
            print(f"\n[{get_elapsed_time_str(overall_start_time)}] The following sources were skipped (disabled):")
            for name in disabled_source_names:
                print(f"  - {name}")

    except Exception as e_critical_outer:
        print(f"\n[{get_elapsed_time_str(overall_start_time)}] A critical error occurred: {e_critical_outer}")
        print(traceback.format_exc())
    finally:
        final_elapsed_time = get_elapsed_time_str(overall_start_time)
        print(f"\n--- [{final_elapsed_time}] Processing Completed ---")

        print("\nOverall Statistics:")
        print(f"  Total Run Time: {final_elapsed_time}")
        print(f"  Attempted Rules (processed or skipped): {live_status.get('session_rules_processed', 0)}")
        print(f"  New Rules Added: {live_status.get('session_rules_added_new', 0)}")
        print(f"  Rules Updated (Content): {live_status.get('session_rules_updated_content', 0)}")
        print(f"  Rules Updated (Timestamp/\u2705): {live_status.get('session_rules_updated_ts', 0)}")
        print(f"  New Versions Created: {live_status.get('session_rules_added_version', 0)}")
        print(f"  Skipped (No Title): {live_status.get('session_rules_skipped_no_title', 0)}")
        print(f"  Skipped (Defective/YAML Error): {live_status.get('session_rules_skipped_defective', 0)}")
        print(f"  Skipped (Other reasons/Unchanged): {live_status.get('session_rules_skipped_other', 0)}")

        print(f"\nSee '{DB_FILE}' for the database and '{RULES_DIR}/' for the rule files.")

if __name__ == '__main__':
    main()
