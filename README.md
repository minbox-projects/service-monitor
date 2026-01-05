# 服务日志与 Docker 监控工具

一个轻量级且功能强大的 Python 工具，用于监控 Docker 容器、健康检查端点、性能指标以及日志文件。它能够发送聚合的邮件告警以及定时的状态报告。

## 功能特性
- **Docker 监控**：检查容器是否运行，并监控其性能指标（CPU/内存）。
- **性能指标**：基于阈值的 CPU 和内存使用率告警（针对多核系统已标准化为 0-100%）。
- **系统资源监控**：监控宿主机的 CPU、内存、磁盘空间及网络 I/O，支持静默采集与高阈值告警。
- **健康检查**：定期的 HTTP（状态码）和 TCP（端口连通性）探测。
- **日志监控**：实时追踪日志文件，支持正则关键字匹配和错误频率阈值。
- **智能告警**：
    - **去重**：避免因同一错误重复发送邮件。
    - **聚合**：将时间窗口内的多条告警汇总为一封邮件发送。
    - **环境感知**：邮件标题自动包含服务器的主机名和内网 IP。
- **定时报告**：支持配置多个每日摘要报告时间，报告中包含所有服务状态及**服务器系统健康指标**。

## 安装与设置

1. **前提条件**
   - Python 3.x
   - Docker（如果需要监控容器）
   - `requests` 库

2. **安装依赖**
   ```bash
   pip install -r requirements.txt
   ```

3. **配置文件**
   编辑 `config.yaml` 来配置你的环境和服务。
   
   ```yaml
   # 邮件发送设置
   email:
     smtp_server: "smtp.example.com"
     smtp_port: 465
     username: "monitor@example.com"
     password: "your-password"
     sender: "monitor@example.com"
     use_ssl: true
     receivers: ["admin@example.com"]

   # 全局告警设置
   alert_config:
     cooldown_seconds: 300       # 同一类型告警的冷却时间（5分钟）
     aggregation_window: 60      # 等待 60 秒以聚合多条告警

   # 全局错误关键字（支持正则）
   error_keywords:
     - "OutOfMemoryError"
     - "Connection refused"

   # 定时报告时间
   reporting:
     times:
       - "08:00"
       - "18:00"

   # 监控服务列表
   services:
     - name: "api-server"
       docker_container_name: "api-container"
       metrics:
         memory_threshold: 80  # 占系统总内存的百分比
         cpu_threshold: 90     # 占系统总算力的百分比（归一化为 0-100%）
       health_check:
         type: "http"
         url: "http://localhost:8080/health"
         interval: 30          # 检测间隔（秒）
       log_file_path: "/var/log/api/error.log"
       log_rules:
         error_threshold_count: 5     # 仅当错误数 > 5 时告警
         error_threshold_window: 60   # ... 统计窗口为 60 秒内

     - name: "redis"
       health_check:
         type: "tcp"
         host: "localhost"
         port: 6379

   # 系统资源监控配置
   system_resources:
     enabled: true
     check_interval: 60           # 检查间隔（秒）
     # 硬盘
     disk:
       path: "/"
       alert_threshold: 90        # 使用率超过 90% 告警
     # 内存
     memory:
       alert_threshold: 90
     # CPU
     cpu:
       alert_threshold: 90
       duration_seconds: 300      # 持续 5 分钟超过阈值才告警
     # 网络IO
     network:
       interface: "eth0"              # 留空自动检测默认网卡
   ```

4. **运行监控**
   ```bash
   python3 monitor.py [可选的配置文件路径]
   ```
   
   后台运行：
   ```bash
   nohup python3 -u monitor.py > monitor.log 2>&1 &
   ```

## 部署为系统服务 (Ubuntu/Systemd)

1. **移动服务文件到系统目录**：
   ```bash
   sudo cp service-monitor.service /etc/systemd/system/
   ```

2. **重载配置并启动**：
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable service-monitor
   sudo systemctl start service-monitor
   ```

## CPU 监控逻辑说明
在多核系统上，`docker stats` 显示的 CPU 使用率可能会超过 100%（例如 3 核满载显示 300%）。为了方便配置告警，本工具将使用率**归一化**为相对于**宿主机总算力**的 **0-100%**。
- 设置阈值为 `90%` 意味着该容器占用了整台服务器 90% 的计算能力，无论服务器有多少个核心。

## 告警聚合与去重
- **去重**：如果触发了一个告警（例如“容器宕机”），在 `cooldown_seconds`（默认 5 分钟）内不会再次为同一服务发送相同的告警。
- **聚合**：如果在 `aggregation_window`（默认 60 秒）内发生了 10 个错误（可能跨多个服务），你将收到**一封**包含所有错误详情的汇总邮件，而不是 10 封单独的邮件。
