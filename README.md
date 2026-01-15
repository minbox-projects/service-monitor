# 服务日志与 Docker 监控工具

一个轻量级且功能强大的 Python 工具，用于监控 Docker 容器、健康检查端点、性能指标以及日志文件。它能够发送聚合的邮件告警以及定时的状态报告。

## 功能特性
- **智能告警与去重**：采用后台队列处理告警发送，避免大批量告警时阻塞监控逻辑。
- **优雅停机 (Graceful Shutdown)**：支持 `SIGINT` / `SIGTERM` 信号，确保程序退出时各监控线程安全收尾。
- **混合监控模式**：单个服务可同时进行健康检查（HTTP/TCP）与 Docker 容器监控（状态及资源）。
- **智能推断**：只需配置 `docker_container_name`，系统将自动开启 Docker 监控，无需显式声明类型。
- **健康检查**：支持 HTTP（状态码）、TCP（端口连通性）以及显式的 Docker 检查。
- **性能指标**：基于阈值的 CPU 和内存使用率告警（针对多核系统已标准化为 0-100%）。
- **系统资源监控**：监控宿主机的 CPU、内存、磁盘空间及网络 I/O，支持静默采集与高阈值告警。
- **日志监控**：实时追踪日志文件，支持正则关键字匹配和错误频率阈值。
- **智能告警策略**：
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
   # 日志存储设置
   logging:
     enabled: true
     file_path: "./logs/monitor.log"
     max_bytes: 10485760      # 10MB
     backup_count: 5          # 保留 5 个备份

   # 邮件发送设置
   email:
     smtp_server: "smtp.example.com"
     smtp_port: 465
     username: "monitor@example.com"
     password: "your-password"
     sender: "monitor@example.com"
     use_ssl: true    # 启用 SSL (通常端口 465)
     use_tls: false   # 启用 TLS (通常端口 587)
     receivers: 
       - "admin@example.com"

   # 全局告警设置
   alert_config:
     cooldown_seconds: 300       # 同类型告警冷却时间 (秒)
     aggregation_window: 60      # 告警聚合发送窗口 (秒)

   # 全局错误关键字（支持正则，适用于未单独配置 log_rules 的服务）
   error_keywords:
     - "OutOfMemoryError"
     - "Connection refused"
     - "ERROR"
     - "Exception"

   # 全局重启关键字 (所有开启 auto_restart 的服务都会继承这些规则)
   global_restart_keywords:
     - "OutOfMemoryError"

   # 定时报告时间 (每日发送摘要)
   reporting:
     times:
       - "08:00"
       - "18:00"

   # 系统资源监控 (宿主机)
   system_resources:
     enabled: true
     check_interval: 60           # 检查间隔 (秒)
     cpu:
       alert_threshold: 90        # 总使用率阈值 (%)
       duration_seconds: 300      # 持续高负载时间触发告警 (秒)
     memory:
       alert_threshold: 90        # 内存使用率阈值 (%)
     disk:
       path: "/"                  # 监控的分区路径
       alert_threshold: 90        # 磁盘使用率阈值 (%)
     network:
       interface: ""              # 网卡名称 (留空自动检测，如 eth0)

   # 监控服务列表
   services:
     # 示例 1: 全功能监控 (HTTP健康检查 + Docker资源 + 日志)
     - name: "api-server"
       docker_container_name: "api-container"
       # Docker 性能指标
       metrics:
         memory_threshold: 80     # 容器内存限额百分比
         cpu_threshold: 90        # 容器CPU限额百分比 (归一化 0-100%)
       # 健康检查 (混合模式: 同时检查 HTTP 和 Docker 状态)
       health_check:
         type: "http"             # http, tcp, 或 docker
         url: "http://localhost:8080/health"
         timeout: 5               # 请求超时 (秒)
         interval: 30             # 检查间隔 (秒)
       # 日志监控
       log_file_path: "/var/log/api/error.log"
       error_keywords:                # [可选] 该服务特有的错误关键字 (与全局关键字合并)
         - "ApiAuthFailed"
         - "DatabaseDeadlock"
       log_rules:
         error_threshold_count: 5     # 触发告警的最小错误数
         error_threshold_window: 60   # 统计窗口 (秒)
       auto_restart:                  # [可选] 自动重启策略
         enabled: true
         keywords:                    # [可选] 服务特有的重启关键字 (与全局合并)
           - "CriticalFailure"
         cooldown: 300                # [可选] 重启冷却时间

     # 示例 2: 仅 Docker 监控 (自动推断模式)
     - name: "worker-node"
       docker_container_name: "worker-container"
       health_check:
         interval: 10             # 仅配置间隔，自动开启 Docker 检查

     # 示例 3: TCP 端口检查
     - name: "redis-db"
       health_check:
         type: "tcp"
         host: "localhost"
         port: 6379
         timeout: 3
   ```

   ### 配置参数详解

   | 参数路径 (Path) | 说明 (Description) | 默认值 (Default) | 单位 (Unit) |
   | :--- | :--- | :--- | :--- |
   | **`logging`** | **日志存储配置** | | |
   | `logging.enabled` | 是否启用日志文件存储 | `false` | - |
   | `logging.file_path` | 日志文件路径 | `monitor.log` | - |
   | `logging.max_bytes` | 单个日志文件最大大小 | `10MB` | Bytes |
   | `logging.backup_count` | 保留的历史日志文件数量 | `5` | 个 |
   | **`email`** | **邮件发送配置** | | |
   | `email.smtp_server` | SMTP 服务器地址 | (Required) | - |
   | `email.smtp_port` | SMTP 端口 | `465` | - |
   | `email.use_ssl` | 是否使用 SSL 加密 | `false` | - |
   | `email.use_tls` | 是否使用 STARTTLS | `true` | - |
   | `email.receivers` | 接收告警的邮箱列表 | (Required) | - |
   | **`alert_config`** | **全局告警策略** | | |
   | `alert_config.cooldown_seconds` | 同类告警冷却时间 (避免刷屏) | `300` | 秒 (s) |
   | `alert_config.aggregation_window` | 告警聚合发送窗口 (合并告警) | `60` | 秒 (s) |
   | `error_keywords` | **全局错误关键字列表** (正则) | `[]` | - |
   | `global_restart_keywords` | **[New]** 全局重启关键字列表 (对所有开启重启的服务生效) | `[]` | - |
   | **`reporting`** | **定时报告** | | |
   | `reporting.times` | 每日发送摘要的时间点列表 | `["08:00"]` | HH:MM |
   | **`services`** | **服务监控 (列表项)** | | |
   | `services[].name` | 服务唯一标识名 | (Required) | - |
   | `services[].docker_container_name` | 容器名称 (设置即自动开启容器监控) | - | - |
   | `services[].metrics.memory_threshold`| 容器内存告警阈值 | - | % |
   | `services[].metrics.cpu_threshold` | 容器 CPU 告警阈值 (归一化 0-100%) | - | % |
   | `services[].health_check.interval` | 检查间隔 (适用于 HTTP/TCP/Docker) | `30` | 秒 (s) |
   | `services[].health_check.type` | 检查类型 (`http`/`tcp`/`docker`) | 自动推断 | - |
   | `services[].health_check.url` | HTTP 检查地址 | - | - |
   | `services[].health_check.host` | TCP 检查主机地址 | `localhost` | - |
   | `services[].health_check.port` | TCP 检查端口 | - | - |
   | `services[].health_check.timeout` | 请求超时时间 | `5` (HTTP), `3` (TCP) | 秒 (s) |
   | `services[].log_file_path` | 需监控的日志文件绝对路径 | - | - |
   | `services[].error_keywords` | **[New]** 服务特有的错误关键字列表 (与全局合并) | `[]` | - |
   | `services[].log_rules.error_threshold_count` | 日志告警触发的最小错误次数 | `1` | 次 |
   | `services[].log_rules.error_threshold_window` | 日志错误计数的滑动窗口 | `60` | 秒 (s) |
   | `services[].auto_restart.enabled` | **[New]** 是否启用自动重启 | `false` | - |
   | `services[].auto_restart.keywords` | **[New]** 仅针对匹配这些正则的错误才重启 | `[]` (全部) | - |
   | `services[].auto_restart.cooldown` | **[New]** 自动重启的冷却时间 | `300` | 秒 (s) |
   | **`system_resources`** | **宿主机资源监控** | | |
   | `system_resources.enabled` | 是否开启系统资源监控 | `false` | - |
   | `system_resources.check_interval` | 资源检查间隔 | `60` | 秒 (s) |
   | `system_resources.cpu.alert_threshold` | 系统 CPU 总使用率阈值 | `90` | % |
   | `system_resources.cpu.duration_seconds` | CPU 持续高负载触发告警的最短时间 | `300` | 秒 (s) |
   | `system_resources.memory.alert_threshold` | 系统内存使用率阈值 | `90` | % |
   | `system_resources.disk.path` | 监控的磁盘挂载路径 | `/` | - |
   | `system_resources.disk.alert_threshold` | 磁盘使用率阈值 | `90` | % |
   | `system_resources.network.interface` | 监控的网络接口 (留空自动检测) | - | - |

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

## 日志监控关键字关系说明
日志监控采用组合与过滤逻辑：

1.  **第一级：监控关键字集合 (Monitor Set)**
    *   程序会合并 **全局配置** (`error_keywords`) 和 **服务单独配置** (`services[].error_keywords`) 的关键字。
    *   **逻辑**：`监控集合 = 全局关键字 U 服务关键字`
    *   只要日志行匹配该集合中 **任意** 一个关键字，就会被计入错误并发送告警。

2.  **第二级：重启关键字 (Restart Filter)**
    *   当错误被捕获后，程序会进一步检查该行是否匹配 **重启关键字集合**。
    *   **集合构成**：`全局重启关键字 (global_restart_keywords) U 服务重启关键字 (auto_restart.keywords)`
    *   **逻辑**：只有当日志行 **同时** 属于“监控集合”且匹配“重启关键字集合”时，才会触发自动重启。

**场景示例：**
*   **全局配置**：`error_keywords: ["OutOfMemory"]`, `global_restart_keywords: ["OutOfMemory"]`
*   **服务A 配置**：`error_keywords: ["Timeout"]`, `auto_restart.keywords: ["Timeout"]`

**结果：**
*   遇到 `OutOfMemory` -> 触发全局规则 -> **报警** -> 匹配全局重启列表 -> **报警并重启**
*   遇到 `Timeout` -> 触发服务A规则 -> **报警** -> 匹配服务A重启列表 -> **报警并重启**
*   遇到 `Exception` -> 不在任何列表 -> **忽略**

## 自动重启功能限制
**自动重启 (Auto-Restart) 功能仅适用于 Docker 部署的服务。**

*   **生效条件**：服务配置中必须包含 `docker_container_name` 字段。
*   **适用场景**：通过日志监控发现错误（如 OOM）时触发重启。
*   **不适用场景**：
    *   纯 TCP/HTTP 监控（未绑定 Docker 容器的服务）。
    *   健康检查（Health Check）失败（目前仅发送告警，不自动重启）。

## 注意事项 (Important Notes)

1.  **Docker 权限**
    *   运行此脚本的用户需要具有访问 Docker Daemon 的权限。
    *   **宿主机运行**：通常需要用户属于 `docker` 组。
    *   **容器内运行**：必须将宿主机的 `/var/run/docker.sock` 挂载到容器中。

2.  **日志轮转 (Log Rotation)**
    *   本工具支持 `copytruncate`（复制并截断）模式的日志轮转，或文件内容不断追加的模式。
    *   **不完全支持**传统的 `move/create`（重命名后新建）模式。如果日志文件被移动且创建了新文件，监控程序可能无法自动切换到新文件，建议配置 Logrotate 使用 `copytruncate` 选项。

3.  **启动即时性**
    *   程序启动时会自动跳到日志文件的**末尾**开始监控。
    *   这意味着启动**之前**产生的历史错误日志不会被检测到，监控仅针对启动后新产生的日志。

4.  **配置更新**
    *   配置文件仅在程序启动时读取一次。如果修改了 `config.yaml`，请务必**重启**监控进程以使配置生效。