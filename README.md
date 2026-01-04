# Service Log & Docker Monitor

A lightweight Python tool to monitor Docker containers and tail log files for errors, sending email alerts when issues are detected.

## Features
- **Docker Monitoring**: Checks if specified containers are running.
- **Log Monitoring**: Tails log files in real-time for specific error keywords (regex supported).
- **Email Alerts**: Sends email notifications with rate limiting (cooldown) to avoid spam.
- **Daily Status Summary**: Automatically sends a summary email of all services' status at 08:00 every morning.

## Setup

1. **Prerequisites**
   - Python 3.x
   - Docker (if monitoring containers)

2. **Installation**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configuration**
   Edit `config.yaml` to set up your email details and services to monitor.
   
   ```yaml
   # config.yaml example
   email:
     smtp_server: "smtp.gmail.com"
     smtp_port: 587
     username: "me@gmail.com"
     password: "app-password"
     sender: "me@gmail.com"
     receivers: ["admin@company.com"]

   error_keywords:
     - "ERROR"
     - "OutOfMemory"

   services:
     - name: "My Service"
       docker_container_name: "my-service-container" # Optional
       log_file_path: "/var/logs/my-service/error.log"
   ```

4. **Running the Monitor**
   ```bash
   python3 monitor.py [optional_config_path]
   ```
   
   To run in background:
   ```bash
   nohup python3 -u monitor.py > monitor.log 2>&1 &
   ```

## Deployment as System Service (Ubuntu/Systemd)

For permanent background execution and auto-restart on boot, use the provided `service-monitor.service` file. 

**Note**: Ensure the `WorkingDirectory` and `ExecStart` paths in `service-monitor.service` match your server deployment path (e.g., `/home/huanwei/monitor`).

1. **Move service file to system directory**:
   ```bash
   sudo cp service-monitor.service /etc/systemd/system/
   ```

2. **Reload and start**:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable service-monitor
   sudo systemctl start service-monitor
   ```

3. **Check status and logs**:
   ```bash
   sudo systemctl status service-monitor
   # Use -f to tail logs and -u for specific service
   sudo journalctl -u service-monitor -f
   ```

## Notes
- The monitor handles log rotation (basic detection).
- It will verify file existence on startup and wait if the file is missing.
- Email alerts have a default 5-minute cooldown per service.
- **Daily Summary**: The summary report is sent at 08:00 AM server time and includes container status and log file metadata.
