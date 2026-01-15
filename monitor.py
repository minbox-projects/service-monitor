import time
import yaml
import os
import re
import smtplib
import threading
import signal
import sys
import schedule
import socket
import logging
from logging.handlers import RotatingFileHandler
from email.mime.text import MIMEText
from datetime import datetime
from collections import defaultdict, deque
from typing import List, Dict, Any, Optional, Tuple, Pattern
import queue
import random
import string

# Try imports
try:
    import docker
except ImportError:
    docker = None

try:
    import requests
except ImportError:
    requests = None

try:
    import psutil
except ImportError:
    psutil = None

def setup_logging(config_data):
    """Setup global logging based on configuration."""
    log_cfg = config_data.get('logging', {})
    if not log_cfg.get('enabled', False):
        # Basic console logging if disabled
        logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
        return

    file_path = log_cfg.get('file_path', 'monitor.log')
    # Ensure directory exists
    os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
    
    max_bytes = log_cfg.get('max_bytes', 10 * 1024 * 1024)
    backup_count = log_cfg.get('backup_count', 5)

    handler = RotatingFileHandler(
        file_path, 
        maxBytes=max_bytes, 
        backupCount=backup_count,
        encoding='utf-8'
    )
    
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
    handler.setFormatter(formatter)
    
    # Root logger
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    
    # Clear existing handlers to avoid duplicates
    if logger.hasHandlers():
        logger.handlers.clear()
        
    logger.addHandler(handler)
    
    # Add console handler as well to see output in terminal
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    logging.info(f"Logging initialized. Writing to: {file_path}")

def get_host_info():
    hostname = socket.gethostname()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('10.254.254.254', 1))
        ip = s.getsockname()[0]
        s.close()
    except Exception:
        ip = '127.0.0.1'
    return hostname, ip

class Config:
    def __init__(self, config_path):
        with open(config_path, 'r') as f:
            self.data = yaml.safe_load(f)
        
        self.email_config = self.data.get('email', {})
        self.services = self.data.get('services', [])
        self.keywords = [re.compile(k) for k in self.data.get('error_keywords', [])]
        self.restart_keywords = [re.compile(k) for k in self.data.get('global_restart_keywords', [])]
        self.reporting_times = self.data.get('reporting', {}).get('times', ['08:00'])
        
        # Alert Config
        alert_cfg = self.data.get('alert_config', {})
        self.alert_cooldown = alert_cfg.get('cooldown_seconds', 300)
        self.aggregation_window = alert_cfg.get('aggregation_window', 60)

class EmailSender:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.hostname, self.ip = get_host_info()

    def send_email_immediate(self, subject: str, body: str, is_alert: bool = True) -> None:
        """Send an email immediately. Note: This is now called from a background thread to avoid blocking."""
        msg = MIMEText(body, 'plain', 'utf-8')
        subject_prefix = f"[{self.hostname} ({self.ip})]"
        msg['Subject'] = f"{subject_prefix} {'[ALERT]' if is_alert else '[INFO]'} {subject}"
        msg['From'] = self.config['sender']
        
        receivers = self.config['receivers']
        if isinstance(receivers, str):
            receivers = [receivers]
        msg['To'] = ", ".join(receivers)
        
        msg['Date'] = datetime.now().strftime('%a, %d %b %Y %H:%M:%S %z')
        msg['Message-ID'] = f"<{datetime.now().timestamp()}@{self.hostname}>"

        try:
            logging.info(f"Sending email: {subject} to {receivers}")
            smtp_server = self.config['smtp_server']
            smtp_port = self.config['smtp_port']
            use_ssl = self.config.get('use_ssl', False)
            use_tls = self.config.get('use_tls', True)

            if use_ssl:
                server = smtplib.SMTP_SSL(smtp_server, smtp_port)
            else:
                server = smtplib.SMTP(smtp_server, smtp_port)
            
            with server:
                if not use_ssl and use_tls:
                    server.starttls()
                server.login(self.config['username'], self.config['password'])
                server.sendmail(self.config['sender'], receivers, msg.as_string())
            logging.info("Email sent successfully.")
        except Exception as e:
            logging.error(f"Failed to send email: {e}")

class RateLimiter:
    """Simple rate limiter to prevent email bombing."""
    def __init__(self, max_emails: int = 50, window_seconds: int = 3600):
        self.max_emails = max_emails
        self.window_seconds = window_seconds
        self.history = deque()
        self.lock = threading.Lock()

    def check_limit(self) -> bool:
        """Check if email can be sent based on global limits."""
        with self.lock:
            now = time.time()
            # Remove expired samples
            while self.history and self.history[0] < now - self.window_seconds:
                self.history.popleft()
            
            if len(self.history) < self.max_emails:
                self.history.append(now)
                return True
            return False

    def get_count(self) -> int:
        with self.lock:
            return len(self.history)

class AlertManager(threading.Thread):
    """
    Handles alert deduplication, aggregation, and sending via a background queue.
    Optimization: Separated email sending and alert collection to avoid locking the main logic.
    """
    def __init__(self, email_sender: EmailSender, cooldown_seconds: int = 300, aggregation_window: int = 60, service_map: Dict[str, Any] = None, rate_limit_config: Dict[str, Any] = None):
        super().__init__()
        self.email_sender = email_sender
        self.cooldown = cooldown_seconds
        self.window = aggregation_window
        self.service_map = service_map or {}
        self.daemon = True
        self.stop_event = threading.Event()
        
        # Anti-spam and anti-bombing
        self.rate_limiter = RateLimiter(
            max_emails=rate_limit_config.get('max_per_hour', 50) if rate_limit_config else 50,
            window_seconds=3600
        )
        
        self.pending_alerts = [] # List of alert dicts
        self.last_sent = {} # Key: signature, Value: timestamp
        self.lock = threading.Lock()
        self.last_flush_time = time.time()
        
        self.mail_queue = queue.Queue()
        self.sender_thread = threading.Thread(target=self._sender_loop, daemon=True)
        self.sender_thread.start()

    def add_alert(self, service_name: str, subject: str, message: str, immediate: bool = False) -> None:
        """Add an alert to be processed."""
        with self.lock:
            signature = f"{service_name}:{subject}"
            now = time.time()
            
            last_time = self.last_sent.get(signature, 0)
            if now - last_time < self.cooldown:
                logging.debug(f"[{service_name}] Suppressing alert '{subject}' (Cooldown active)")
                return

            self.pending_alerts.append({
                'service': service_name,
                'subject': subject,
                'message': message,
                'time': datetime.now().strftime('%H:%M:%S'),
                'signature': signature
            })
            
            if immediate:
                logging.info(f"[{service_name}] Immediate flush requested for: {subject}")
                self._flush_pending()
            
    def run(self) -> None:
        while not self.stop_event.is_set():
            time.sleep(5)
            self._check_flush()
        
        # Final flush on stop
        with self.lock:
            self._flush_pending()

    def _check_flush(self) -> None:
        with self.lock:
            if not self.pending_alerts:
                return
            
            if time.time() - self.last_flush_time < self.window:
                return

            self._flush_pending()

    def _flush_pending(self) -> None:
        # NOTE: This method must be called with self.lock held
        if not self.pending_alerts:
            return

        logging.info(f"Packaging {len(self.pending_alerts)} alerts for background sending...")
        
        grouped_msg = ["Monitor Alerts Report", "====================="]
        
        for alert in self.pending_alerts:
            self.last_sent[alert['signature']] = time.time()
            service_name = alert['service']
            grouped_msg.append(f"\n[{alert['time']}] Service: {service_name}")
            
            if service_name in self.service_map:
                log_path = self.service_map[service_name].get('log_file_path')
                if log_path:
                    grouped_msg.append(f"Log File: {log_path}")
            
            grouped_msg.append(f"Subject: {alert['subject']}")
            grouped_msg.append(f"Detail: {alert['message']}")
            grouped_msg.append("-" * 30)

        full_body = "\n".join(grouped_msg)
        
        if len(self.pending_alerts) == 1:
            subject = f"{self.pending_alerts[0]['service']}: {self.pending_alerts[0]['subject']}"
        else:
            subject = f"Multiple Alerts ({len(self.pending_alerts)})"

        # Anti-spam: Add unique ID to subject
        unique_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=4))
        subject = f"{subject} [ID: {unique_id}]"

        # Anti-bombing: Check global rate limit
        if self.rate_limiter.check_limit():
            # Push to background sender queue
            self.mail_queue.put((subject, full_body, True))
        else:
            logging.warning(f"Global email rate limit exceeded ({self.rate_limiter.max_emails}/hr). Alert summary dropped.")
            # Optionally send a single critical notification if it's the first time exceeding
            if self.rate_limiter.get_count() == self.rate_limiter.max_emails:
                 self.mail_queue.put(("CRITICAL: Email Rate Limit Exceeded", "Global email limit reached. Further alerts will be suppressed for this hour.", True))
        
        self.pending_alerts = []
        self.last_flush_time = time.time()

    def _sender_loop(self) -> None:
        """Background loop to process the email queue."""
        while not self.stop_event.is_set() or not self.mail_queue.empty():
            try:
                # Use a timeout to occasionally check stop_event
                item = self.mail_queue.get(timeout=2)
                subject, body, is_alert = item
                self.email_sender.send_email_immediate(subject, body, is_alert)
                self.mail_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logging.error(f"Error in AlertManager sender loop: {e}")

class LogMonitor(threading.Thread):
    """
    Monitors a log file for specific keywords and triggers alerts or restarts.
    """
    def __init__(self, service_config: Dict[str, Any], global_keywords: List[Pattern], global_restart_keywords: List[Pattern], alert_manager: AlertManager, docker_client: Optional[Any] = None):
        super().__init__()
        self.service_name = service_config['name']
        self.log_path = service_config.get('log_file_path')
        self.alert_manager = alert_manager
        self.stop_event = threading.Event()
        self.daemon = True
        self.docker_client = docker_client
        
        # Merge global keywords with service-specific keywords
        self.keywords = list(global_keywords) # Copy global list
        service_specific_keywords = service_config.get('error_keywords', [])
        for k in service_specific_keywords:
            try:
                self.keywords.append(re.compile(k))
            except re.error as e:
                logging.error(f"[{self.service_name}] Invalid regex in service keywords '{k}': {e}")
        
        # Enhanced Log Analysis Config
        self.log_rules = service_config.get('log_rules', {})
        self.threshold_count = self.log_rules.get('error_threshold_count', 1)
        self.threshold_window = self.log_rules.get('error_threshold_window', 60)
        
        # Auto Restart Config
        restart_cfg = service_config.get('auto_restart', {})
        self.auto_restart = restart_cfg.get('enabled', False)
        try:
            self.restart_cooldown = int(restart_cfg.get('cooldown', 300))
        except (ValueError, TypeError):
            self.restart_cooldown = 300
            logging.warning(f"[{self.service_name}] Invalid restart cooldown config, defaulting to 300s")
        
        # Merge global and local restart keywords
        self.restart_keywords = list(global_restart_keywords)
        for k in restart_cfg.get('keywords', []):
            try:
                self.restart_keywords.append(re.compile(k))
            except re.error as e:
                logging.error(f"[{self.service_name}] Invalid regex in auto_restart keywords '{k}': {e}")
             
        self.last_restart_time = 0
        self.container_name = service_config.get('docker_container_name')
        
        # Docker client is now injected
        if not self.docker_client and self.auto_restart and self.container_name and docker:
            try:
                self.docker_client = docker.from_env()
            except Exception as e:
                logging.error(f"[{self.service_name}] Failed to init Docker client for auto-restart: {e}")

        # Store error timestamps
        self.error_history = deque()

    def run(self) -> None:
        if not self.log_path:
            return

        logging.info(f"[{self.service_name}] Starting log monitor for: {self.log_path}")
        
        while not os.path.exists(self.log_path) and not self.stop_event.is_set():
            time.sleep(5)
        
        if self.stop_event.is_set(): return

        f = None
        try:
            f = open(self.log_path, 'r', encoding='utf-8', errors='ignore')
            # Start at the end of the file to ignore old logs
            f.seek(0, 2)
            # Get the current file's inode to detect rotation
            try:
                cur_ino = os.fstat(f.fileno()).st_ino
            except AttributeError:
                cur_ino = None

            while not self.stop_event.is_set():
                line = f.readline()
                if not line:
                    time.sleep(1)
                    try:
                        if os.path.exists(self.log_path):
                            stat = os.stat(self.log_path)
                            
                            # Check for rotation (inode changed)
                            if cur_ino is not None and stat.st_ino != cur_ino:
                                logging.info(f"[{self.service_name}] Log rotation detected. Reopening {self.log_path}")
                                f.close()
                                f = open(self.log_path, 'r', encoding='utf-8', errors='ignore')
                                cur_ino = os.fstat(f.fileno()).st_ino
                                # New file detected, read from the beginning
                                f.seek(0, 0)
                                continue

                            # Check for truncation (size smaller than current position)
                            if stat.st_size < f.tell():
                                logging.info(f"[{self.service_name}] Log truncation detected. Rewinding.")
                                f.seek(0, 0)
                        
                    except FileNotFoundError:
                        # File might be temporarily missing during rotation
                        pass
                    except Exception as e:
                        logging.error(f"[{self.service_name}] Error checking file state: {e}")
                    continue
                
                self.check_line(line)

        except Exception as e:
            logging.error(f"[{self.service_name}] Error reading log: {e}")
        finally:
            if f:
                f.close()

    def check_line(self, line):
        for keyword in self.keywords:
            if keyword.search(line):
                now = time.time()
                self.error_history.append(now)
                
                # Cleanup old errors
                while self.error_history and self.error_history[0] < now - self.threshold_window:
                    self.error_history.popleft()
                
                # Check threshold
                if len(self.error_history) >= self.threshold_count:
                    self.alert_manager.add_alert(
                        self.service_name,
                        "Log Error Threshold Exceeded",
                        f"Keyword: {keyword.pattern}\nMatched {len(self.error_history)} times in {self.threshold_window}s\nLast Line: {line.strip()}"
                    )
                    
                    if self.auto_restart:
                        should_restart = False
                        if self.restart_keywords:
                            # If specific keywords defined, only restart if one matches the current line
                            for rk in self.restart_keywords:
                                if rk.search(line):
                                    should_restart = True
                                    break
                            
                            if not should_restart:
                                logging.info(f"[{self.service_name}] Auto-restart skipped: Error matched threshold but not restart keywords.")
                        else:
                            # Fallback: Restart on any error if no specific keywords defined
                            should_restart = True

                        if should_restart:
                            self.trigger_restart(keyword.pattern)

                    self.error_history.clear() 
                break

    def trigger_restart(self, reason):
        if not self.docker_client or not self.container_name:
            return
            
        now = time.time()
        if now - self.last_restart_time < self.restart_cooldown:
            logging.info(f"[{self.service_name}] Skipping auto-restart (Cooldown active)")
            return

        try:
            logging.info(f"[{self.service_name}] Triggering AUTO-RESTART due to: {reason}")
            container = self.docker_client.containers.get(self.container_name)
            container.restart()
            self.last_restart_time = now
            
            self.alert_manager.add_alert(
                self.service_name,
                "CRITICAL: Service Auto-Restarted",
                f"Container '{self.container_name}' was restarted automatically.\nReason: Log keyword match '{reason}'",
                immediate=True
            )

            # Start recovery check
            threading.Thread(target=self.wait_for_recovery, args=(self.container_name,), daemon=True).start()

        except Exception as e:
            logging.error(f"[{self.service_name}] Auto-restart failed: {e}")
            self.alert_manager.add_alert(
                self.service_name,
                "Auto-Restart FAILED",
                f"Attempted to restart '{self.container_name}' but failed: {e}"
            )

    def wait_for_recovery(self, container_name):
        """Waits for the container to become running and sends a notification."""
        logging.info(f"[{self.service_name}] Waiting for recovery...")
        
        # Create a local docker client to avoid thread safety issues
        local_docker = None
        if docker:
            try:
                local_docker = docker.from_env()
            except Exception as e:
                logging.error(f"[{self.service_name}] Failed to create local docker client for recovery check: {e}")
                return

        # Check for up to 5 minutes
        max_retries = 30  
        retry_interval = 10
        
        for _ in range(max_retries):
            time.sleep(retry_interval)
            try:
                container = local_docker.containers.get(container_name)
                # Refresh container state
                container.reload()
                if container.status == 'running':
                    self.alert_manager.add_alert(
                        self.service_name,
                        "RECOVERY: Service Restarted Successfully",
                        f"Container '{container_name}' is back to 'running' state after auto-restart.",
                        immediate=True
                    )
                    logging.info(f"[{self.service_name}] Recovery detected and notified.")
                    return
            except Exception as e:
                logging.warning(f"[{self.service_name}] Error checking recovery status: {e}")
        
        logging.error(f"[{self.service_name}] Recovery check timed out (Container not running after 5m).")

class HealthMonitor(threading.Thread):
    """
    Performs HTTP, TCP, or Docker status health checks on services.
    Feature 1: HTTP/TCP Health Checks
    Also handles Docker Container checks (Explicitly or Implicitly).
    """
    def __init__(self, service_config: Dict[str, Any], alert_manager: AlertManager, docker_client: Optional[Any] = None):
        super().__init__()
        self.service_config = service_config
        self.service_name = service_config['name']
        self.config = service_config.get('health_check') or {}
        self.alert_manager = alert_manager
        self.stop_event = threading.Event()
        self.daemon = True
        self.docker_client = docker_client
        
        # Auto Restart Config
        restart_cfg = service_config.get('auto_restart', {})
        self.auto_restart = restart_cfg.get('enabled', False)
        try:
            self.restart_cooldown = int(restart_cfg.get('cooldown', 300))
        except (ValueError, TypeError):
            self.restart_cooldown = 300
        
        self.last_restart_time = 0

    def run(self):
        # Determine which checks to run
        checks = []
        check_type = self.config.get('type')
        
        # 1. Explicit Health Check
        if check_type == 'http':
            checks.append(self.check_http)
        elif check_type == 'tcp':
            checks.append(self.check_tcp)
        elif check_type == 'docker':
            checks.append(self.check_docker)
            
        # 2. Implicit Docker Check
        # If container name exists, and we haven't already added the docker check
        if self.service_config.get('docker_container_name') and self.check_docker not in checks:
            checks.append(self.check_docker)

        if not checks:
            return

        interval = self.config.get('interval', 30)
        check_names = [f.__name__ for f in checks]
        logging.info(f"[{self.service_name}] Starting checks: {', '.join(check_names)} (Interval: {interval}s)")

        while not self.stop_event.is_set():
            for check_func in checks:
                try:
                    check_func()
                except Exception as e:
                    self.alert_manager.add_alert(
                        self.service_name,
                        f"Check Failed",
                        str(e)
                    )
            
            time.sleep(interval)

    def calculate_cpu_percent(self, stats):
        try:
            cpu_delta = stats['cpu_stats']['cpu_usage']['total_usage'] - \
                        stats['precpu_stats']['cpu_usage']['total_usage']
            system_delta = stats['cpu_stats']['system_cpu_usage'] - \
                           stats['precpu_stats']['system_cpu_usage']
            
            if system_delta > 0.0 and cpu_delta > 0.0:
                return (cpu_delta / system_delta) * 100.0
        except KeyError:
            pass
        return 0.0

    def check_docker(self):
        if not self.docker_client:
            self.alert_manager.add_alert(self.service_name, "Docker Check Failed", "Docker client not available")
            return

        container_name = self.service_config.get('docker_container_name')
        if not container_name:
             self.alert_manager.add_alert(self.service_name, "Config Error", "Missing 'docker_container_name'")
             return

        try:
            container = self.docker_client.containers.get(container_name)
            
            # 1. Status Check
            if container.status != 'running':
                # If currently restarting, just log and skip
                if container.status == 'restarting':
                    logging.info(f"[{self.service_name}] Container is currently restarting. Skipping checks.")
                    return

                self.alert_manager.add_alert(
                    self.service_name,
                    f"Container Down",
                    f"Container '{container_name}' status is '{container.status}'"
                )
                
                if self.auto_restart:
                    self.trigger_restart(container_name, container.status)
                    
                return # Skip metrics if down

            # 2. Performance Metrics
            metrics_cfg = self.service_config.get('metrics', {})
            if metrics_cfg:
                stats = container.stats(stream=False)
                
                # Memory
                mem_usage = stats['memory_stats']['usage']
                mem_limit = stats['memory_stats']['limit']
                mem_percent = (mem_usage / mem_limit) * 100.0
                
                mem_threshold = metrics_cfg.get('memory_threshold')
                if mem_threshold and mem_percent > mem_threshold:
                        self.alert_manager.add_alert(
                        self.service_name,
                        "High Memory Usage",
                        f"Usage: {mem_percent:.2f}% (Threshold: {mem_threshold}%)"
                    )

                # CPU
                cpu_percent = self.calculate_cpu_percent(stats)
                cpu_threshold = metrics_cfg.get('cpu_threshold')
                if cpu_threshold and cpu_percent > cpu_threshold:
                        self.alert_manager.add_alert(
                        self.service_name,
                        "High CPU Usage",
                        f"Usage: {cpu_percent:.2f}% (Threshold: {cpu_threshold}%)"
                    )

        except docker.errors.NotFound:
                self.alert_manager.add_alert(
                    self.service_name,
                    f"Container Missing",
                    f"Container '{container_name}' not found"
                )

    def check_http(self):
        if not requests:
            return # Skip if no requests lib
        
        url = self.config.get('url')
        timeout = self.config.get('timeout', 5)
        
        try:
            resp = requests.get(url, timeout=timeout)
            if resp.status_code >= 400:
                 self.alert_manager.add_alert(
                    self.service_name,
                    "HTTP Health Check Failed",
                    f"URL: {url}\nStatus Code: {resp.status_code}"
                )
        except Exception as e:
             self.alert_manager.add_alert(
                self.service_name,
                "HTTP Connection Failed",
                f"URL: {url}\nError: {str(e)}"
            )

    def check_tcp(self):
        host = self.config.get('host', 'localhost')
        port = self.config.get('port')
        timeout = self.config.get('timeout', 3)
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((host, port))
            if result != 0:
                 self.alert_manager.add_alert(
                    self.service_name,
                    "TCP Health Check Failed",
                    f"Host: {host}:{port}\nResult Code: {result} (Not 0)"
                )
        except Exception as e:
            self.alert_manager.add_alert(
                self.service_name,
                "TCP Connection Error",
                str(e)
            )
        finally:
            sock.close()

    def trigger_restart(self, container_name, current_status):
        now = time.time()
        if now - self.last_restart_time < self.restart_cooldown:
            logging.info(f"[{self.service_name}] Skipping health-check auto-restart (Cooldown active)")
            return

        try:
            logging.info(f"[{self.service_name}] Triggering AUTO-RESTART due to status: {current_status}")
            container = self.docker_client.containers.get(container_name)
            container.restart()
            self.last_restart_time = now
            
            self.alert_manager.add_alert(
                self.service_name,
                "CRITICAL: Service Auto-Restarted (Health Check)",
                f"Container '{container_name}' was found in '{current_status}' state and restarted.",
                immediate=True
            )

            # Start recovery check
            threading.Thread(target=self.wait_for_recovery, args=(container_name,), daemon=True).start()

        except Exception as e:
            logging.error(f"[{self.service_name}] Health-check auto-restart failed: {e}")
            self.alert_manager.add_alert(
                self.service_name,
                "Auto-Restart FAILED",
                f"Attempted to restart '{container_name}' but failed: {e}"
            )

    def wait_for_recovery(self, container_name):
        """Waits for the container to become running and sends a notification."""
        logging.info(f"[{self.service_name}] Waiting for recovery...")
        
        # Create a local docker client to avoid thread safety issues
        local_docker = None
        if docker:
            try:
                local_docker = docker.from_env()
            except Exception as e:
                logging.error(f"[{self.service_name}] Failed to create local docker client for recovery check: {e}")
                return

        # Check for up to 5 minutes
        max_retries = 30  
        retry_interval = 10
        
        for _ in range(max_retries):
            time.sleep(retry_interval)
            try:
                container = local_docker.containers.get(container_name)
                # Refresh container state
                container.reload()
                if container.status == 'running':
                    self.alert_manager.add_alert(
                        self.service_name,
                        "RECOVERY: Service Restarted Successfully",
                        f"Container '{container_name}' is back to 'running' state after health-check restart.",
                        immediate=True
                    )
                    logging.info(f"[{self.service_name}] Recovery detected and notified.")
                    return
            except Exception as e:
                logging.warning(f"[{self.service_name}] Error checking recovery status: {e}")
        
        logging.error(f"[{self.service_name}] Recovery check timed out (Container not running after 5m).")

class SystemResourceMonitor(threading.Thread):
    def __init__(self, config: Dict[str, Any], alert_manager: AlertManager):
        super().__init__()
        self.config = config.get('system_resources', {})
        self.alert_manager = alert_manager
        self.daemon = True
        self.stop_event = threading.Event()
        self.check_interval = self.config.get('check_interval', 60)
        
        # Stats for daily report
        self.stats = {
            'cpu_usage_samples': [],
            'net_io_start': None,
            'net_io_current': None
        }
        
        # CPU Alert tracking
        self.cpu_high_start_time = None
        
        # Initialize network counters
        if psutil:
            self.stats['net_io_start'] = psutil.net_io_counters()

    def run(self):
        if not psutil or not self.config.get('enabled', False):
            logging.warning("SystemResourceMonitor disabled or psutil missing.")
            return

        logging.info("SystemResourceMonitor started.")
        while not self.stop_event.is_set():
            try:
                self._check_resources()
            except Exception as e:
                logging.error(f"System check error: {e}")
            time.sleep(self.check_interval)

    def _check_resources(self):
        # 1. Disk Check
        disk_cfg = self.config.get('disk', {})
        if disk_cfg:
            path = disk_cfg.get('path', '/')
            try:
                usage = psutil.disk_usage(path)
                if usage.percent > disk_cfg.get('alert_threshold', 90):
                    self.alert_manager.add_alert(
                        "System Resource Alert",
                        f"Disk usage on '{path}' is critical: {usage.percent}% (Free: {usage.free / (1024**3):.2f} GB)",
                        "system-disk"
                    )
            except Exception as e:
                logging.error(f"Disk check failed: {e}")

        # 2. Memory Check
        mem_cfg = self.config.get('memory', {})
        if mem_cfg:
            mem = psutil.virtual_memory()
            if mem.percent > mem_cfg.get('alert_threshold', 90):
                 self.alert_manager.add_alert(
                    "System Resource Alert",
                    f"Memory usage is critical: {mem.percent}% (Available: {mem.available / (1024**3):.2f} GB)",
                    "system-memory"
                )

        # 3. CPU Check
        cpu_cfg = self.config.get('cpu', {})
        if cpu_cfg:
            cpu_percent = psutil.cpu_percent(interval=1)
            self.stats['cpu_usage_samples'].append(cpu_percent)
            # Keep only last 24h worth of samples (assuming 60s interval) -> 1440 samples
            if len(self.stats['cpu_usage_samples']) > 1440:
                self.stats['cpu_usage_samples'].pop(0)

            threshold = cpu_cfg.get('alert_threshold', 90)
            duration = cpu_cfg.get('duration_seconds', 300)

            if cpu_percent > threshold:
                if self.cpu_high_start_time is None:
                    self.cpu_high_start_time = time.time()
                elif time.time() - self.cpu_high_start_time > duration:
                    self.alert_manager.add_alert(
                        "System Resource Alert",
                        f"CPU usage high for over {duration}s: {cpu_percent}%",
                        "system-cpu"
                    )
            else:
                self.cpu_high_start_time = None

        # 4. Network Stats Update
        self.stats['net_io_current'] = psutil.net_io_counters()

    def get_report_data(self):
        if not psutil:
            return ["System Monitor: psutil not installed"]

        lines = ["[Server Health]", "----------------"]
        
        # Host info
        lines.append(f"Hostname : {socket.gethostname()}")
        
        # CPU
        if self.stats['cpu_usage_samples']:
            avg_cpu = sum(self.stats['cpu_usage_samples']) / len(self.stats['cpu_usage_samples'])
            max_cpu = max(self.stats['cpu_usage_samples'])
            core_count = psutil.cpu_count(logical=True)
            lines.append(f"CPU      : Current: {psutil.cpu_percent()}% ({core_count} Cores) | Avg(24h): {avg_cpu:.1f}% | Peak: {max_cpu:.1f}%")
        
        # Memory
        mem = psutil.virtual_memory()
        lines.append(f"Memory   : Used: {mem.used / (1024**3):.2f}GB / {mem.total / (1024**3):.2f}GB ({mem.percent}%)")
        
        # Disk
        disk_path = self.config.get('disk', {}).get('path', '/')
        try:
            d = psutil.disk_usage(disk_path)
            lines.append(f"Disk ({disk_path}) : {d.percent}% Used (Free: {d.free / (1024**3):.2f}GB)")
        except:
            pass

        # Network
        if self.stats['net_io_start'] and self.stats['net_io_current']:
            curr = self.stats['net_io_current']
            start = self.stats['net_io_start']
            sent = (curr.bytes_sent - start.bytes_sent) / (1024**3)
            recv = (curr.bytes_recv - start.bytes_recv) / (1024**3)
            lines.append(f"Network  : Rx: {recv:.2f}GB | Tx: {sent:.2f}GB (Since start)")

        return lines

class DailySummaryReporter:
    def __init__(self, config: Config, email_sender: EmailSender, system_monitor: Optional[SystemResourceMonitor] = None, docker_client: Optional[Any] = None):
        self.services = config.services
        self.email_sender = email_sender
        self.system_monitor = system_monitor
        self.docker_client = docker_client

    def send_report(self):
        try:
            lines = ["Daily Service Status Summary", "============================"]
            
            if self.system_monitor:
                lines.extend(self.system_monitor.get_report_data())
                lines.append("") # Empty line

            for service in self.services:
                name = service['name']
                lines.append(f"\nService: {name}")
                
                # Docker Status
                container_name = service.get('docker_container_name')
                if container_name:
                    status = "UNKNOWN"
                    if self.docker_client:
                        try:
                            container = self.docker_client.containers.get(container_name)
                            status = container.status.upper()
                        except docker.errors.NotFound:
                            status = "MISSING"
                        except Exception as e:
                            status = f"ERROR: {str(e)}"
                    else:
                        status = "Docker Client Unavailable"
                    lines.append(f"  Container '{container_name}': {status}")
                
                # Health Check Status
                if 'health_check' in service:
                    hc = service['health_check']
                    check_type = hc.get('type', 'Auto/Docker')
                    lines.append(f"  Health Check: Enabled ({check_type})")

                # Log Status
                log_path = service.get('log_file_path')
                if log_path:
                    if os.path.exists(log_path):
                        try:
                            size = os.path.getsize(log_path)
                            modified = datetime.fromtimestamp(os.path.getmtime(log_path)).strftime('%Y-%m-%d %H:%M:%S')
                            lines.append(f"  Log File: {log_path} (Size: {size} bytes, Last Modified: {modified})")
                        except OSError:
                            lines.append(f"  Log File: {log_path} (Cannot read stats)")
                    else:
                        lines.append(f"  Log File: {log_path} (NOT FOUND)")
            
            body = "\n".join(lines)
            logging.info("Sending daily summary...")
            self.email_sender.send_email_immediate("Daily Service Summary", body, is_alert=False)
        except Exception as e:
            logging.error(f"Failed to generate or send daily report: {e}")

def main():
    if len(sys.argv) > 1:
        config_path = sys.argv[1]
    else:
        config_path = 'config.yaml'
        
    if not os.path.exists(config_path):
        print(f"Error: Config file not found at {config_path}", file=sys.stderr)
        return

    config = Config(config_path)
    setup_logging(config.data)
    
    email_sender = EmailSender(config.email_config)
    
    # Initialize Global Docker Client
    global_docker = None
    if docker:
        try:
            global_docker = docker.from_env()
            logging.info("Global Docker client initialized.")
        except Exception as e:
            logging.error(f"Failed to initialize global Docker client: {e}")

    # Initialize Alert Manager
    service_map = {s['name']: s for s in config.services}
    alert_manager = AlertManager(
        email_sender, 
        config.alert_cooldown, 
        config.aggregation_window,
        service_map,
        rate_limit_config=config.data.get('alert_config', {}).get('rate_limit')
    )
    alert_manager.start()
    
    # Initialize System Monitor
    system_monitor = SystemResourceMonitor(config.data, alert_manager)
    system_monitor.start()

    threads = []

    for service in config.services:
        # Start Log Monitors
        if service.get('log_file_path'):
            t = LogMonitor(service, config.keywords, config.restart_keywords, alert_manager, docker_client=global_docker)
            t.start()
            threads.append(t)
        
        # Start Health Monitors (Explicit or Implicit via Docker)
        if service.get('health_check') or service.get('docker_container_name'):
            t = HealthMonitor(service, alert_manager, docker_client=global_docker)
            t.start()
            threads.append(t)

    # Setup Scheduled Summaries
    summary_reporter = DailySummaryReporter(config, email_sender, system_monitor, docker_client=global_docker)
    for report_time in config.reporting_times:
        schedule.every().day.at(report_time).do(summary_reporter.send_report)
        logging.info(f"Daily summary scheduled for {report_time}.")

    logging.info("Monitor service started. Press Ctrl+C to stop.")

    def signal_handler(sig, frame):
        logging.info("Shutdown signal received. Stopping monitors...")
        
        # Signal all threads to stop
        alert_manager.stop_event.set()
        system_monitor.stop_event.set()
        for t in threads:
            t.stop_event.set()
        
        # Wait for threads to finish (graceful shutdown)
        logging.info("Waiting for threads to exit...")
        alert_manager.join(timeout=5)
        system_monitor.join(timeout=5)
        for t in threads:
            t.join(timeout=2)
            
        logging.info("All monitors stopped. Exiting.")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Keep main thread alive and run schedule
    while True:
        try:
            schedule.run_pending()
        except Exception as e:
            logging.error(f"Error in scheduled task: {e}")
        time.sleep(1)

if __name__ == "__main__":
    main()
