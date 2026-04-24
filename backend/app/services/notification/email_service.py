"""
预警邮件发送（从 subscription 流程中抽离，供统一通知入口复用）。
"""
from __future__ import annotations

import io
import logging
import os
import smtplib
from datetime import datetime, timedelta, timezone
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

logger = logging.getLogger("uvicorn.error")

BEIJING_TZ = timezone(timedelta(hours=8))


def beijing_now() -> datetime:
    return datetime.now(BEIJING_TZ)


def beijing_datetime_to_naive(dt: datetime) -> datetime:
    """与 subscription 模块一致：入库用 naive 北京时间。"""
    if dt.tzinfo is not None:
        if dt.tzinfo != BEIJING_TZ:
            dt = dt.astimezone(BEIJING_TZ)
        return dt.replace(tzinfo=None)
    return dt


def _load_local_dotenv_if_present():
    try:
        from dotenv import load_dotenv
    except Exception:
        return
    try:
        api_dir = os.path.dirname(os.path.abspath(__file__))
        backend_root = os.path.abspath(os.path.join(api_dir, "..", "..", ".."))
        project_root = os.path.abspath(os.path.join(api_dir, "..", "..", "..", ".."))
        cwd = os.getcwd()
        explicit = os.getenv("DOTENV_PATH")
        candidates = []
        if explicit:
            candidates.append(explicit)
        candidates.extend(
            [
                os.path.join(cwd, ".env"),
                os.path.join(project_root, ".env"),
                os.path.join(backend_root, ".env"),
            ]
        )
        for p in candidates:
            if os.path.exists(p):
                load_dotenv(p, override=False)
                break
    except Exception:
        return


_load_local_dotenv_if_present()

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.example.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM = os.getenv("SMTP_FROM", "noreply@example.com")
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() == "true"


def send_alert_email(user_email: str, alert_data: dict, domains_csv_content: Optional[bytes]):
    """
    发送预警邮件（正文摘要+CSV附件）
    """
    if not SMTP_USER or not SMTP_PASSWORD:
        logger.warning("SMTP配置不完整，跳过邮件发送")
        return

    try:
        msg = MIMEMultipart()
        msg["From"] = SMTP_FROM
        msg["To"] = user_email
        msg["Subject"] = f"域名检测预警 - {alert_data.get('model_name', '未知模型')}"

        all_domains = alert_data.get("high_risk_domains", [])
        domain_type = "恶意域名" if alert_data.get("task_type") == "malicious" else "仿冒域名"

        preview_domains = all_domains[:20]
        body = f"""您好，

检测到{domain_type}预警，详情如下：

模型名称：{alert_data.get('model_name', '未知')}
任务类型：{'恶意性检测' if alert_data.get('task_type') == 'malicious' else '仿冒域名检测'}
检测域名总数：{alert_data.get('detected_count', 0)}
{domain_type}数量：{alert_data.get('high_risk_count', 0)}
检测时间：{alert_data.get('created_at', '')}

{domain_type}列表（前20个，完整列表请查看附件）：
"""
        for i, domain in enumerate(preview_domains, 1):
            body += f"{i}. {domain}\n"

        if len(all_domains) > 20:
            body += f"\n... 还有 {len(all_domains) - 20} 个{domain_type}，请查看附件获取完整列表。\n"

        body += """
请及时处理。

此邮件由系统自动发送，请勿回复。
        """

        msg.attach(MIMEText(body, "plain", "utf-8"))

        if domains_csv_content:
            attachment = MIMEBase("application", "octet-stream")
            attachment.set_payload(domains_csv_content)
            encoders.encode_base64(attachment)

            task_type_label = "malicious" if alert_data.get("task_type") == "malicious" else "phishing"
            timestamp = beijing_now().strftime("%Y%m%d_%H%M%S")
            filename = f"{task_type_label}_domains_{timestamp}.csv"
            attachment.add_header(
                "Content-Disposition",
                f"attachment; filename*=utf-8''{filename}",
            )
            msg.attach(attachment)

        if SMTP_PORT == 465:
            server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT)
        else:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
            if SMTP_USE_TLS:
                server.starttls()

        server.login(SMTP_USER, SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()

        logger.info(f"预警邮件已发送至: {user_email}，包含 {len(all_domains)} 个{domain_type}")
    except Exception as e:
        logger.exception(f"发送预警邮件失败: {e}")
