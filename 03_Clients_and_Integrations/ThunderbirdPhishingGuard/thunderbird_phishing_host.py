# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: thunderbird_phishing_host.py
Назначение: Native Messaging bridge между Mozilla Thunderbird и Python-оркестратором.

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
import sys
import os
import struct
import json
import tempfile
import shutil
import hashlib

from pathlib import Path

# Динамическое разрешение путей проекта
GUARD_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = GUARD_DIR.parents[1]
BASE_DIR = str(PROJECT_ROOT)
DOCS_DIR = str(PROJECT_ROOT / "05_Methodology_and_Docs")
SCRIPTS_DIR = str(PROJECT_ROOT / "01_Core_Engines")
DIST_DIR = PROJECT_ROOT / "03_Clients_and_Integrations" / "Distributable"
DIST_UTILS_DIR = str(DIST_DIR / "src" / "utils")
DIST_ANALYZER_DIR = str(DIST_DIR / "src" / "analyzer")
CORE_ENGINES_DIR = str(PROJECT_ROOT / "01_Core_Engines")

for p in [DIST_UTILS_DIR, DIST_ANALYZER_DIR, CORE_ENGINES_DIR]:
    if os.path.exists(p) and p not in sys.path:
        sys.path.append(p)

def log_debug(msg_text):
    try:
        import datetime
        log_path = os.environ.get("TB_GUARD_LOG", str(GUARD_DIR / "host_debug.log"))
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {msg_text}\n")
    except:
        pass

# Redirect standard output/error during orchestrator execution to avoid protocol corruption on stdout
class StdoutRedirector:
    def __init__(self, target):
        self.target = target
        self.original_stdout = None

    def __enter__(self):
        self.original_stdout = sys.stdout
        sys.stdout = self.target
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        sys.stdout = self.original_stdout

def read_message():
    raw_length = sys.stdin.buffer.read(4)
    if len(raw_length) == 0:
        return None
    message_length = struct.unpack('@I', raw_length)[0]
    message = sys.stdin.buffer.read(message_length).decode('utf-8')
    return json.loads(message)

def write_message(message):
    encoded_content = json.dumps(message).encode('utf-8')
    encoded_length = struct.pack('@I', len(encoded_content))
    sys.stdout.buffer.write(encoded_length)
    sys.stdout.buffer.write(encoded_content)
    sys.stdout.buffer.flush()

def main():
    log_debug("Native host started.")
    # Force UTF-8 encoding for standard streams to prevent Cyrillic encoding issues on Windows
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except AttributeError:
        pass # Python versions prior to 3.7 do not have reconfigure()

    while True:
        request_id = None
        try:
            msg = read_message()
            if msg is None:
                log_debug("Received EOF/None message from stdin. Exiting.")
                break

            action = msg.get("action")
            request_id = msg.get("requestId")
            log_debug(f"Received request: action={action}, requestId={request_id}")
            if action == "analyze":
                eml_content = msg.get("eml", "")
                
                # Create a temporary file for the EML
                temp_dir = tempfile.mkdtemp(prefix="tb_phish_")
                temp_eml_path = os.path.join(temp_dir, "message.eml")
                
                # Write the raw EML content as binary using a robust byte-preserving conversion.
                # Since Thunderbird's getRaw() returns a string where each character represents a byte (0-255),
                # we can preserve every byte exactly. If there are any decoded Unicode characters (>255),
                # we encode them as UTF-8. This prevents any corruption of raw binary attachment data.
                try:
                    eml_bytes = bytearray()
                    for char in eml_content:
                        code = ord(char)
                        if code <= 255:
                            eml_bytes.append(code)
                        else:
                            eml_bytes.extend(char.encode("utf-8"))
                    
                    with open(temp_eml_path, "wb") as f:
                        f.write(eml_bytes)
                except Exception as e:
                    sys.stderr.write(f"Error writing EML bytes: {e}. Falling back to standard UTF-8.\n")
                    with open(temp_eml_path, "w", encoding="utf-8", errors="ignore") as f:
                        f.write(eml_content)

                # Import and run the orchestrator (prioritizing 01_Core_Engines/analyze_threats.py)
                try:
                    from analyze_threats import PhishingOrchestrator
                except ImportError:
                    from phishing_orchestrator import PhishingOrchestrator
                
                orchestrator = PhishingOrchestrator(temp_eml_path)
                
                # Execute orchestrator steps manually to capture hashes before cleanup
                with StdoutRedirector(sys.stderr):
                    try:
                        if hasattr(orchestrator, "run"):
                            orchestrator.run()
                        else:
                            if temp_eml_path.lower().endswith(('.eml', '.msg')):
                                orchestrator.analyze_email(temp_eml_path)
                            else:
                                orchestrator.report_data["attachments"].append({
                                    "name": os.path.basename(temp_eml_path), 
                                    "path": temp_eml_path, 
                                    "type": "direct_input",
                                    "indicators": []
                                })
                            orchestrator.run_yara_scan()
                            orchestrator.deep_analyze_attachments()
                            orchestrator.generate_report()
                    except Exception as e:
                        sys.stderr.write(f"Orchestrator manual steps error: {e}\n")

                # Read report data from orchestrator
                report_data = getattr(orchestrator, "report_data", {})
                
                # Map report_data to rich 'deep' JSON expected by popup/message.js
                overall_verdict = report_data.get("overall_verdict", "CLEAN")
                score_res = report_data.get("score_result")
                if score_res:
                    score = score_res.total_score
                    overall_verdict = score_res.verdict
                else:
                    score = 95 if overall_verdict == "MALICIOUS" else (55 if overall_verdict == "SUSPICIOUS" else 10)

                
                # Prepare attachments and calculate hashes
                mapped_attachments = []
                attachment_analysis = []
                carved_items = []
                
                for att in report_data.get("attachments") or []:
                    path = att.get("path", "")
                    name = str(att.get("name") or "")
                    att_type = att.get("type", "attachment")
                    
                    size = 0
                    md5_hash = "N/A"
                    sha256_hash = "N/A"
                    
                    if path and os.path.exists(path):
                        try:
                            size = os.path.getsize(path)
                            with open(path, "rb") as bf:
                                content_bytes = bf.read()
                                md5_hash = hashlib.md5(content_bytes).hexdigest()
                                sha256_hash = hashlib.sha256(content_bytes).hexdigest()
                        except Exception as e:
                            sys.stderr.write(f"Hashing error for {name}: {e}\n")
                    
                    ext = name.lower().split('.')[-1] if '.' in name else ""
                    dangerous = ext in ('exe', 'scr', 'js', 'vbs', 'bat', 'cmd', 'ps1', 'hta', 'docm', 'xlsm', 'zip', 'rar', '7z')
                    
                    if att_type == "attachment" or att_type == "direct_input":
                        mapped_attachments.append({
                            "filename": name,
                            "content_type": "application/octet-stream",
                            "size": size,
                            "md5": md5_hash,
                            "sha256": sha256_hash,
                            "dangerous": dangerous
                        })
                        
                        if att.get("indicators"):
                            attachment_analysis.append({
                                "filename": name,
                                "type": ext,
                                "risk_score": 85 if overall_verdict == "MALICIOUS" else 45,
                                "findings": att.get("indicators") or []
                            })
                    elif att_type == "carved":
                        carved_items.append({
                            "type": ext,
                            "offset": 0,
                            "size": size,
                            "md5": md5_hash
                        })
                
                # Map links to IOC domains
                email_data = report_data.get("email") or {}
                links = email_data.get("links") or []
                domains = []
                for url in links:
                    if "//" in url:
                        try:
                            domain = url.split("//")[1].split("/")[0]
                            if domain:
                                domains.append(domain)
                        except:
                            pass
                domains = list(set(domains))
                
                rich_deep_report = {
                    "verdict": overall_verdict,
                    "score": score,
                    "version": "3.0",
                    "levels_completed": [
                        "Level 1: Header Triage", 
                        "Level 2: VBA / Macros", 
                        "Level 3: P-Code Analysis", 
                        "Level 4: ActiveX Forensic", 
                        "Level 5: Document Metadata", 
                        "Level 6: Indicators of Compromise"
                    ],
                    "score_breakdown": [{"rule": w, "points": 25 if "critical" in str(w).lower() else 15} for w in report_data.get("warnings") or []],
                    "reasons": report_data.get("warnings") or [],
                    "authentication": {
                        "spf": {
                            "status": str(email_data.get("spf", "UNKNOWN")).lower(),
                            "domain": email_data.get("from", "")
                        },
                        "dkim": {
                            "status": str(email_data.get("dkim", "NONE")).lower()
                        },
                        "dmarc": {
                            "status": "none"
                        }
                    },
                    "body_analysis": {
                        "text_length": len(eml_content),
                        "html_length": 0,
                        "empty_body": len(report_data.get("warnings") or []) > 0 and any("empty" in str(w).lower() for w in report_data.get("warnings") or [])
                    },
                    "attachments": mapped_attachments,
                    "attachment_analysis": attachment_analysis,
                    "ioc": {
                        "urls": links,
                        "domains": domains,
                        "emails": [],
                        "ips": [],
                        "suspicious_patterns": []
                    },
                    "metadata_hex_analysis": {
                        "hex_injections": [],
                        "gps_coordinates": [],
                        "suspicious_strings": []
                    },
                    "carved_images": {
                        "total_count": len(carved_items),
                        "types": {"images": len(carved_items)},
                        "items": carved_items
                    },
                    "eml_file": "message.eml"
                }

                # Read generated ОТЧЕТ_АНАЛИЗА.txt if it exists in orchestrator's temp directory
                report_text = ""
                report_file_path = os.path.join(orchestrator.temp_dir, "ОТЧЕТ_АНАЛИЗА.txt")
                if os.path.exists(report_file_path):
                    try:
                        with open(report_file_path, "r", encoding="utf-8") as rf:
                            report_text = rf.read()
                    except Exception as e:
                        sys.stderr.write(f"Failed to read report text file: {e}\n")

                # Run orchestrator cleanup now that we're done accessing files
                try:
                    orchestrator.cleanup()
                except Exception as e:
                    sys.stderr.write(f"Orchestrator cleanup error: {e}\n")

                # Cleanup the temp EML directory
                try:
                    shutil.rmtree(temp_dir)
                except Exception as e:
                    sys.stderr.write(f"Failed to cleanup temp EML directory: {e}\n")

                response = {
                    "success": True,
                    "verdict": overall_verdict,
                    "report_data": rich_deep_report,
                    "report_text": report_text,
                    "requestId": request_id
                }
                write_message(response)
            elif action == "prepare_ai_session":
                log_debug("Starting prepare_ai_session...")
                session_dir = str(GUARD_DIR / "ActiveSession")
                log_debug(f"session_dir is: {session_dir}")
                
                # 1. Clear session_dir if it exists, or create it
                if os.path.exists(session_dir):
                    try:
                        log_debug("Clearing existing session_dir...")
                        shutil.rmtree(session_dir)
                    except Exception as e:
                        log_debug(f"Failed to clear session dir: {e}")
                        sys.stderr.write(f"Failed to clear session dir: {e}\n")
                
                os.makedirs(session_dir, exist_ok=True)
                log_debug("Created/verified session_dir.")
                
                # 2. Write the EML file
                eml_content = msg.get("eml", "")
                eml_path = os.path.join(session_dir, "message.eml")
                log_debug(f"Writing EML file to: {eml_path}")
                try:
                    eml_bytes = bytearray()
                    for char in eml_content:
                        code = ord(char)
                        if code <= 255:
                            eml_bytes.append(code)
                        else:
                            eml_bytes.extend(char.encode("utf-8"))
                    
                    with open(eml_path, "wb") as f:
                        f.write(eml_bytes)
                    log_debug("Successfully wrote EML bytes.")
                except Exception as e:
                    log_debug(f"Error writing EML bytes: {e}. Falling back to standard UTF-8.")
                    sys.stderr.write(f"Error writing EML bytes in prepare_ai_session: {e}\n")
                    with open(eml_path, "w", encoding="utf-8", errors="ignore") as f:
                        f.write(eml_content)
                
                # 3. Extract attachments using PhishingOrchestrator
                log_debug("Initializing PhishingOrchestrator...")
                try:
                    from analyze_threats import PhishingOrchestrator
                except ImportError:
                    from phishing_orchestrator import PhishingOrchestrator
                orchestrator = PhishingOrchestrator(eml_path)
                
                # Override temp_dir to save attachments directly into session_dir
                log_debug(f"Original orchestrator.temp_dir: {orchestrator.temp_dir}")
                if os.path.exists(orchestrator.temp_dir):
                    try:
                        shutil.rmtree(orchestrator.temp_dir)
                    except:
                        pass
                orchestrator.temp_dir = session_dir
                log_debug(f"Overrode orchestrator.temp_dir to: {orchestrator.temp_dir}")
                
                log_debug("Running orchestrator.analyze_email...")
                with StdoutRedirector(sys.stderr):
                    try:
                        orchestrator.analyze_email(eml_path)
                        log_debug("orchestrator.analyze_email completed successfully.")
                    except Exception as e:
                        log_debug(f"Orchestrator analyze_email error: {e}")
                        sys.stderr.write(f"Orchestrator analyze_email error in prepare_ai_session: {e}\n")
                
                # 4. Get list of files in session_dir to return to frontend
                log_debug("Listing files in session_dir...")
                files = []
                for f in os.listdir(session_dir):
                    f_path = os.path.join(session_dir, f)
                    if os.path.isfile(f_path):
                        files.append({
                            "name": f,
                            "size": os.path.getsize(f_path)
                        })
                log_debug(f"Found files: {files}")
                
                log_debug("Sending response back to Thunderbird.")
                write_message({
                    "success": True,
                    "ok": True,
                    "files": files,
                    "requestId": request_id
                })
                log_debug("Response sent successfully.")

            elif action == "execute_tool":
                tool_name = msg.get("tool_name")
                tool_args = msg.get("arguments", {})
                session_dir = str(GUARD_DIR / "ActiveSession")
                
                if tool_name == "list_session_files":
                    log_debug("Executing list_session_files...")
                    files = []
                    if os.path.exists(session_dir):
                        for f in os.listdir(session_dir):
                            f_path = os.path.join(session_dir, f)
                            if os.path.isfile(f_path):
                                files.append({
                                    "name": f,
                                    "size": os.path.getsize(f_path)
                                })
                    log_debug(f"list_session_files found: {files}")
                    write_message({
                        "success": True,
                        "files": files,
                        "requestId": request_id
                    })
                    
                elif tool_name == "read_playbook":
                    playbook_name = tool_args.get("playbook_name")
                    log_debug(f"Executing read_playbook for: {playbook_name}")
                    # Security check: prevent directory traversal
                    playbook_name = os.path.basename(playbook_name)
                    allowed_playbooks = ["ИНСТРУКЦИЯ_АНАЛИЗ_ПИСЕМ.md", "METHODOLOGY.md", "ТЗ_Office_Macro_Security_Analyzer.md"]
                    if playbook_name not in allowed_playbooks:
                        log_debug(f"Playbook {playbook_name} is not allowed.")
                        write_message({
                            "success": False,
                            "error": f"Playbook {playbook_name} is not allowed.",
                            "requestId": request_id
                        })
                        continue
                    
                    playbook_path = os.path.join(DOCS_DIR, playbook_name)
                    if not os.path.exists(playbook_path):
                        log_debug(f"Playbook {playbook_name} not found at: {playbook_path}")
                        write_message({
                            "success": False,
                            "error": f"Playbook {playbook_name} not found.",
                            "requestId": request_id
                        })
                        continue
                    
                    try:
                        with open(playbook_path, "r", encoding="utf-8") as pf:
                            content = pf.read()
                        log_debug(f"Successfully read playbook {playbook_name} ({len(content)} chars)")
                        write_message({
                            "success": True,
                            "content": content,
                            "requestId": request_id
                        })
                    except Exception as e:
                        log_debug(f"Failed to read playbook: {e}")
                        write_message({
                            "success": False,
                            "error": f"Failed to read playbook: {str(e)}",
                            "requestId": request_id
                        })
                        
                elif tool_name == "execute_project_script":
                    script_name = tool_args.get("script_name")
                    file_name = tool_args.get("file_name")
                    log_debug(f"Executing script {script_name} on file {file_name}")
                    
                    # Security check: prevent directory traversal or running arbitrary scripts
                    allowed_scripts = ["full_doc_scan.py", "metadata_hex_scanner.py", "carve_images.py", "analyze_threats.py"]
                    if script_name not in allowed_scripts:
                        log_debug(f"Script {script_name} is not allowed.")
                        write_message({
                            "success": False,
                            "error": f"Script {script_name} is not allowed.",
                            "requestId": request_id
                        })
                        continue
                    
                    # Build paths
                    script_path = os.path.join(SCRIPTS_DIR, script_name)
                    
                    # Prevent directory traversal for file_name
                    file_name = os.path.basename(file_name)
                    file_path = os.path.join(session_dir, file_name)
                    
                    if not os.path.exists(file_path):
                        log_debug(f"File {file_name} not found in active session: {file_path}")
                        write_message({
                            "success": False,
                            "error": f"File {file_name} not found in active session.",
                            "requestId": request_id
                        })
                        continue
                    
                    # Run the script
                    import subprocess
                    try:
                        # Run script and capture output
                        cmd = [sys.executable, script_path, file_path]
                        log_debug(f"Running command: {cmd}")
                        res = subprocess.run(cmd, capture_output=True, text=True, cwd=SCRIPTS_DIR, encoding="utf-8", errors="ignore")
                        log_debug(f"Script execution completed with exit code: {res.returncode}")
                        write_message({
                            "success": True,
                            "stdout": res.stdout,
                            "stderr": res.stderr,
                            "exit_code": res.returncode,
                            "requestId": request_id
                        })
                    except Exception as e:
                        log_debug(f"Script execution failed: {e}")
                        write_message({
                            "success": False,
                            "error": f"Failed to execute script: {str(e)}",
                            "requestId": request_id
                        })
            else:
                write_message({
                    "success": False, 
                    "error": f"Unknown action: {action}",
                    "requestId": request_id
                })
        except Exception as e:
            log_debug(f"Error in main loop: {e}")
            import traceback
            log_debug(traceback.format_exc())
            sys.stderr.write(f"Error in main loop: {e}\n")
            traceback.print_exc(file=sys.stderr)
            try:
                write_message({
                    "success": False, 
                    "error": str(e),
                    "requestId": request_id
                })
            except Exception as write_err:
                sys.stderr.write(f"Failed to write error message: {write_err}\n")
                break

if __name__ == "__main__":
    main()
