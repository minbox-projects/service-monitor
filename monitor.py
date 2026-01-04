import time
import yaml
import os
import re
import smtplib
import threading
import signal
import sys
import schedule
from email.mime.text import MIMEText
from datetime import datetime

# Try to import docker, handle if not installed
try:
    import docker
except ImportError:
    docker = None

class Config:
    def __init__(self, config_path):
        with open(config_path, 'r') as f:
            self.data = yaml.safe_load(f)
        
        self.email_config = self.data.get('email', {})
        self.services = self.data.get('services', [])
        self.keywords = [re.compile(k) for k in self.data.get('error_keywords', [])]

class EmailSender:
    def __init__(self, config):
        self.config = config
        self.last_sent = {} # Key: service_name, Value: timestamp
        self.cooldown = 300 # 5 minutes cooldown between alerts for the same service

    def send_email(self, subject, body, service_name=None):
        # Check cooldown
        if service_name:
            last = self.last_sent.get(service_name, 0)
            if time.time() - last < self.cooldown:
                print(f"[{datetime.now()}] Suppressing alert for {service_name} due to cooldown.")
                return

        msg = MIMEText(body)
        msg['Subject'] = f"[ALERT] {subject}" if service_name else f"[INFO] {subject}"
        msg['From'] = self.config['sender']
        msg['To'] = ", ".join(self.config['receivers'])

        try:
            print(f"[{datetime.now()}] Sending email {'alert' if service_name else 'notification'} for {service_name if service_name else 'System'}...")
            
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
                server.sendmail(self.config['sender'], self.config['receivers'], msg.as_string())
            
            print(f"[{datetime.now()}] Email sent successfully.")
            if service_name:
                self.last_sent[service_name] = time.time()
        except Exception as e:
            print(f"Failed to send email: {e}")

class LogMonitor(threading.Thread):
    def __init__(self, service_config, global_keywords, email_sender):
        super().__init__()
        self.service_name = service_config['name']
        self.log_path = service_config.get('log_file_path')
        self.keywords = global_keywords
        self.email_sender = email_sender
        self.running = True
        self.daemon = True

    def run(self):
        if not self.log_path:
            return

        print(f"[{self.service_name}] Starting log monitor for: {self.log_path}")
        
        # Wait for file to exist
        while not os.path.exists(self.log_path) and self.running:
            time.sleep(5)
        
        if not self.running: return

        # Open file and go to the end
        try:
            with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
                # Seek to end
                f.seek(0, 2)
                
                while self.running:
                    line = f.readline()
                    if not line:
                        time.sleep(1)
                        # Check if file was rotated (size became smaller or inode changed - simplified check here)
                        try:
                            if os.stat(self.log_path).st_size < f.tell():
                                f.seek(0, 0) # File truncated or new file, start from beginning
                        except FileNotFoundError:
                            break # File gone
                        continue
                    
                    self.check_line(line)
        except Exception as e:
            print(f"[{self.service_name}] Error reading log: {e}")

    def check_line(self, line):
        for keyword in self.keywords:
            if keyword.search(line):
                body = f"Service: {self.service_name}\nDetected error keyword: {keyword.pattern}\n\nLog Line:\n{line.strip()}"
                self.email_sender.send_email(f"Error detected in {self.service_name}", body, self.service_name)
                break

class DockerMonitor(threading.Thread):
    def __init__(self, services, email_sender):
        super().__init__()
        self.services = services
        self.email_sender = email_sender
        self.running = True
        self.daemon = True
        try:
            self.client = docker.from_env() if docker else None
        except Exception as e:
            print(f"Docker connection failed: {e}")
            self.client = None

    def run(self):
        if not self.client:
            print("Docker client not available. Skipping container checks.")
            return

        print("Starting Docker container monitor...")
        
        while self.running:
            for service in self.services:
                container_name = service.get('docker_container_name')
                if not container_name:
                    continue

                try:
                    container = self.client.containers.get(container_name)
                    if container.status != 'running':
                        self.email_sender.send_email(
                            f"Container {container_name} is DOWN", 
                            f"The docker container '{container_name}' for service '{service['name']}' is currently '{container.status}'.",
                            service['name']
                        )
                except docker.errors.NotFound:
                    self.email_sender.send_email(
                        f"Container {container_name} MISSING", 
                        f"The docker container '{container_name}' for service '{service['name']}' could not be found.",
                        service['name']
                    )
                except Exception as e:
                    print(f"Error checking container {container_name}: {e}")
            
            time.sleep(10) # Check every 10 seconds

class DailySummaryReporter:
    def __init__(self, config, email_sender):
        self.services = config.services
        self.email_sender = email_sender
        try:
            self.docker_client = docker.from_env() if docker else None
        except Exception:
            self.docker_client = None

    def send_report(self):
        lines = ["Daily Service Status Summary", "============================"]
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
            
            # Log Status
            log_path = service.get('log_file_path')
            if log_path:
                if os.path.exists(log_path):
                    try:
                        size = os.path.getsize(log_path)
                        modified = datetime.fromtimestamp(os.path.getmtime(log_path)).strftime('%Y-%m-%d %H:%M:%S')
                        lines.append(f"  Log File: Exists (Size: {size} bytes, Last Modified: {modified})")
                    except OSError:
                        lines.append(f"  Log File: Exists (Cannot read stats)")
                else:
                    lines.append(f"  Log File: NOT FOUND")
        
        body = "\n".join(lines)
        print(f"[{datetime.now()}] Sending daily summary...")
        self.email_sender.send_email("Daily Service Summary", body)

def main():
    if len(sys.argv) > 1:
        config_path = sys.argv[1]
    else:
        config_path = 'config.yaml'
        
    if not os.path.exists(config_path):
        print(f"Config file not found at {config_path}")
        return

    config = Config(config_path)
    email_sender = EmailSender(config.email_config)

    threads = []

    # Start Log Monitors
    for service in config.services:
        t = LogMonitor(service, config.keywords, email_sender)
        t.start()
        threads.append(t)

    # Start Docker Monitor
    docker_monitor = DockerMonitor(config.services, email_sender)
    docker_monitor.start()
    threads.append(docker_monitor)

    # Setup Daily Summary
    summary_reporter = DailySummaryReporter(config, email_sender)
    schedule.every().day.at("08:00").do(summary_reporter.send_report)
    print("Daily summary scheduled for 08:00.")

    print("Monitor service started. Press Ctrl+C to stop.")

    def signal_handler(sig, frame):
        print("\nStopping monitors...")
        for t in threads:
            t.running = False
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    # Keep main thread alive and run schedule
    while True:
        schedule.run_pending()
        time.sleep(1)

if __name__ == "__main__":
    main()
