_current_lang = 'en'
_current_dict = None
_fallback_dict = None

_translations = {
    'en': {
        # email subject tags
        'email.alert_tag': '[ALERT]',
        'email.info_tag': '[INFO]',

        # alert manager flush
        'alert.report_title': 'Monitor Alerts Report',
        'alert.service_label': 'Service: {service}',
        'alert.log_file_label': 'Log File: {path}',
        'alert.subject_label': 'Subject: {subject}',
        'alert.detail_label': 'Detail: {detail}',
        'alert.multiple': 'Multiple Alerts ({count})',
        'alert.rate_limit_exceeded': 'CRITICAL: Email Rate Limit Exceeded',
        'alert.rate_limit_body': 'Global email limit reached. Further alerts will be suppressed for this hour.',
        'alert.rate_limit_warning': 'Global email rate limit exceeded ({max}/hr). Alert summary dropped.',

        # backoff / suppression
        'backoff.suppressed_summary': '[Suppressed {count} identical alerts since last notification]',
        'backoff.recovery_msg': "Alert '{subject}' has not recurred for {elapsed}s.",
        'backoff.suppressed_during': '[{count} alerts were suppressed during this incident]',
        'backoff.recovered_prefix': 'RECOVERED: {subject}',

        # log monitor
        'log.error_threshold': 'Log Error Threshold Exceeded',
        'log.error_detail': 'Keyword: {keyword}\nMatched {count} times in {window}s\nLast Line: {line}',
        'log.restart_critical': 'CRITICAL: Service Auto-Restarted',
        'log.restart_detail': "Container '{container}' was restarted automatically.\nReason: Log keyword match '{reason}'",
        'log.restart_failed': 'Auto-Restart FAILED',
        'log.restart_failed_detail': "Attempted to restart '{container}' but failed: {error}",
        'log.recovery_success': 'RECOVERY: Service Restarted Successfully',
        'log.recovery_detail': "Container '{container}' is back to 'running' state after auto-restart.",

        # health monitor
        'health.docker_unavailable': 'Docker client not available',
        'health.docker_check_failed': 'Docker Check Failed',
        'health.config_error': 'Config Error',
        'health.missing_container_name': "Missing 'docker_container_name'",
        'health.container_down': 'Container Down',
        'health.container_status': "Container '{container}' status is '{status}'",
        'health.high_memory': 'High Memory Usage',
        'health.high_cpu': 'High CPU Usage',
        'health.usage_threshold': 'Usage: {percent:.2f}% (Threshold: {threshold}%)',
        'health.container_missing': 'Container Missing',
        'health.container_not_found': "Container '{container}' not found",
        'health.http_failed': 'HTTP Health Check Failed',
        'health.http_detail': 'URL: {url}\nStatus Code: {code}',
        'health.http_conn_failed': 'HTTP Connection Failed',
        'health.http_conn_detail': 'URL: {url}\nError: {error}',
        'health.tcp_failed': 'TCP Health Check Failed',
        'health.tcp_detail': 'Host: {host}:{port}\nResult Code: {code} (Not 0)',
        'health.tcp_conn_error': 'TCP Connection Error',
        'health.check_failed': 'Check Failed',
        'health.restart_critical': 'CRITICAL: Service Auto-Restarted (Health Check)',
        'health.restart_detail': "Container '{container}' was found in '{status}' state and restarted.",
        'health.restart_failed': 'Auto-Restart FAILED',
        'health.restart_failed_detail': "Attempted to restart '{container}' but failed: {error}",
        'health.recovery_success': 'RECOVERY: Service Restarted Successfully',
        'health.recovery_detail': "Container '{container}' is back to 'running' state after health-check restart.",

        # system resource monitor
        'sys.alert_name': 'System Resource Alert',
        'sys.disk_critical': "Disk usage on '{path}' is critical: {percent}% (Free: {free:.2f} GB)",
        'sys.memory_critical': 'Memory usage is critical: {percent}% (Available: {available:.2f} GB)',
        'sys.cpu_high': 'CPU usage high for over {duration}s: {percent}%',
        'sys.psutil_missing': 'System Monitor: psutil not installed',

        # daily report
        'report.title': 'Daily Service Status Summary',
        'report.subject': 'Daily Service Summary',
        'report.server_health': '[Server Health]',
        'report.hostname': 'Hostname : {hostname}',
        'report.cpu': 'CPU      : Current: {current}% ({cores} Cores) | Avg(24h): {avg:.1f}% | Peak: {peak:.1f}%',
        'report.memory': 'Memory   : Used: {used:.2f}GB / {total:.2f}GB ({percent}%)',
        'report.disk': 'Disk ({path}) : {percent}% Used (Free: {free:.2f}GB)',
        'report.network': 'Network  : Rx: {recv:.2f}GB | Tx: {sent:.2f}GB (Since start)',
        'report.service_label': 'Service: {name}',
        'report.container_status': "  Container '{container}': {status}",
        'report.docker_unavailable': 'Docker Client Unavailable',
        'report.status_missing': 'MISSING',
        'report.status_unknown': 'UNKNOWN',
        'report.status_error': 'ERROR: {error}',
        'report.health_check': '  Health Check: Enabled ({type})',
        'report.log_file_stats': '  Log File: {path} (Size: {size} bytes, Last Modified: {modified})',
        'report.log_file_unreadable': '  Log File: {path} (Cannot read stats)',
        'report.log_file_missing': '  Log File: {path} (NOT FOUND)',
    },
    'zh': {
        # email subject tags
        'email.alert_tag': '[告警]',
        'email.info_tag': '[通知]',

        # alert manager flush
        'alert.report_title': '监控告警报告',
        'alert.service_label': '服务: {service}',
        'alert.log_file_label': '日志文件: {path}',
        'alert.subject_label': '标题: {subject}',
        'alert.detail_label': '详情: {detail}',
        'alert.multiple': '多条告警 ({count})',
        'alert.rate_limit_exceeded': '严重: 邮件发送频率超限',
        'alert.rate_limit_body': '全局邮件限制已达上限，后续告警将在本小时内被抑制。',
        'alert.rate_limit_warning': '全局邮件频率超限 ({max}/小时)，告警摘要已丢弃。',

        # backoff / suppression
        'backoff.suppressed_summary': '[自上次通知以来已抑制 {count} 条相同告警]',
        'backoff.recovery_msg': "告警 '{subject}' 已 {elapsed} 秒未复发。",
        'backoff.suppressed_during': '[本次事件期间共抑制 {count} 条告警]',
        'backoff.recovered_prefix': '已恢复: {subject}',

        # log monitor
        'log.error_threshold': '日志错误阈值超限',
        'log.error_detail': '关键词: {keyword}\n在 {window} 秒内匹配 {count} 次\n最后一行: {line}',
        'log.restart_critical': '严重: 服务已自动重启',
        'log.restart_detail': "容器 '{container}' 已自动重启。\n原因: 日志关键词匹配 '{reason}'",
        'log.restart_failed': '自动重启失败',
        'log.restart_failed_detail': "尝试重启 '{container}' 失败: {error}",
        'log.recovery_success': '恢复: 服务重启成功',
        'log.recovery_detail': "容器 '{container}' 在自动重启后已恢复运行。",

        # health monitor
        'health.docker_unavailable': 'Docker 客户端不可用',
        'health.docker_check_failed': 'Docker 检查失败',
        'health.config_error': '配置错误',
        'health.missing_container_name': "缺少 'docker_container_name' 配置",
        'health.container_down': '容器停止运行',
        'health.container_status': "容器 '{container}' 状态为 '{status}'",
        'health.high_memory': '内存使用率过高',
        'health.high_cpu': 'CPU 使用率过高',
        'health.usage_threshold': '使用率: {percent:.2f}% (阈值: {threshold}%)',
        'health.container_missing': '容器不存在',
        'health.container_not_found': "容器 '{container}' 未找到",
        'health.http_failed': 'HTTP 健康检查失败',
        'health.http_detail': 'URL: {url}\n状态码: {code}',
        'health.http_conn_failed': 'HTTP 连接失败',
        'health.http_conn_detail': 'URL: {url}\n错误: {error}',
        'health.tcp_failed': 'TCP 健康检查失败',
        'health.tcp_detail': '地址: {host}:{port}\n返回码: {code} (非 0)',
        'health.tcp_conn_error': 'TCP 连接错误',
        'health.check_failed': '检查失败',
        'health.restart_critical': '严重: 服务已自动重启 (健康检查)',
        'health.restart_detail': "容器 '{container}' 处于 '{status}' 状态，已自动重启。",
        'health.restart_failed': '自动重启失败',
        'health.restart_failed_detail': "尝试重启 '{container}' 失败: {error}",
        'health.recovery_success': '恢复: 服务重启成功',
        'health.recovery_detail': "容器 '{container}' 在健康检查重启后已恢复运行。",

        # system resource monitor
        'sys.alert_name': '系统资源告警',
        'sys.disk_critical': "磁盘 '{path}' 使用率严重: {percent}% (剩余: {free:.2f} GB)",
        'sys.memory_critical': '内存使用率严重: {percent}% (可用: {available:.2f} GB)',
        'sys.cpu_high': 'CPU 使用率持续超过 {duration} 秒: {percent}%',
        'sys.psutil_missing': '系统监控: 未安装 psutil',

        # daily report
        'report.title': '每日服务状态摘要',
        'report.subject': '每日服务摘要',
        'report.server_health': '[服务器健康状态]',
        'report.hostname': '主机名   : {hostname}',
        'report.cpu': 'CPU      : 当前: {current}% ({cores} 核) | 24h均值: {avg:.1f}% | 峰值: {peak:.1f}%',
        'report.memory': '内存     : 已用: {used:.2f}GB / {total:.2f}GB ({percent}%)',
        'report.disk': '磁盘 ({path}) : 已用 {percent}% (剩余: {free:.2f}GB)',
        'report.network': '网络     : 接收: {recv:.2f}GB | 发送: {sent:.2f}GB (自启动)',
        'report.service_label': '服务: {name}',
        'report.container_status': "  容器 '{container}': {status}",
        'report.docker_unavailable': 'Docker 客户端不可用',
        'report.status_missing': '不存在',
        'report.status_unknown': '未知',
        'report.status_error': '错误: {error}',
        'report.health_check': '  健康检查: 已启用 ({type})',
        'report.log_file_stats': '  日志文件: {path} (大小: {size} 字节, 最后修改: {modified})',
        'report.log_file_unreadable': '  日志文件: {path} (无法读取状态)',
        'report.log_file_missing': '  日志文件: {path} (未找到)',
    },
}


def init(lang='en'):
    global _current_lang, _current_dict, _fallback_dict
    _current_lang = lang if lang in _translations else 'en'
    _current_dict = _translations[_current_lang]
    _fallback_dict = _translations['en']


def t(key, **kwargs):
    text = _current_dict.get(key) if _current_dict is not None else None
    if text is None:
        text = _fallback_dict.get(key, key) if _fallback_dict is not None else key
    if kwargs:
        try:
            return text.format(**kwargs)
        except (KeyError, ValueError, IndexError):
            return text
    return text
