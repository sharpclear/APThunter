"""
预警邮件发送（从 subscription 流程中抽离，供统一通知入口复用）。
"""
from __future__ import annotations

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


def _smtp_configured() -> bool:
    return bool(SMTP_USER and SMTP_PASSWORD)


def _build_message(*, user_email: str, subject: str, body: str) -> MIMEMultipart:
    msg = MIMEMultipart()
    msg["From"] = SMTP_FROM
    msg["To"] = user_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain", "utf-8"))
    return msg


def _attach_bytes(
    msg: MIMEMultipart,
    *,
    content: bytes,
    filename: str,
    maintype: str = "application",
    subtype: str = "octet-stream",
) -> None:
    attachment = MIMEBase(maintype, subtype)
    attachment.set_payload(content)
    encoders.encode_base64(attachment)
    attachment.add_header(
        "Content-Disposition",
        f"attachment; filename*=utf-8''{filename}",
    )
    msg.attach(attachment)


def _send_message(msg: MIMEMultipart) -> None:
    if SMTP_PORT == 465:
        server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT)
    else:
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
        if SMTP_USE_TLS:
            server.starttls()

    try:
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.send_message(msg)
    finally:
        server.quit()


def send_alert_email(user_email: str, alert_data: dict, domains_attachment_content: Optional[bytes]):
    """
    发送预警邮件（正文摘要+Excel附件）
    """
    if not _smtp_configured():
        logger.warning("SMTP配置不完整，跳过邮件发送")
        return

    try:
        all_domains = alert_data.get("high_risk_domains", [])
        task_type = alert_data.get("task_type")
        if task_type == "impersonation":
            domain_type = "仿冒域名"
            task_type_text = "仿冒域名检测"
        elif task_type == "history_similarity":
            domain_type = "历史高度相似域名"
            task_type_text = "历史高度相似检测"
        else:
            domain_type = "恶意域名"
            task_type_text = "恶意性检测"

        preview_domains = all_domains[:20]
        body = f"""您好，

检测到{domain_type}预警，详情如下：

模型名称：{alert_data.get('model_name', '未知')}
任务类型：{task_type_text}
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
        msg = _build_message(
            user_email=user_email,
            subject=f"域名检测预警 - {alert_data.get('model_name', '未知模型')}",
            body=body,
        )

        if domains_attachment_content:
            if task_type == "impersonation":
                task_type_label = "phishing"
            elif task_type == "history_similarity":
                task_type_label = "history_similarity"
            else:
                task_type_label = "malicious"
            timestamp = beijing_now().strftime("%Y%m%d_%H%M%S")
            filename = f"{task_type_label}_domains_{timestamp}.xlsx"
            _attach_bytes(
                msg,
                content=domains_attachment_content,
                filename=filename,
                subtype="vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )

        _send_message(msg)

        logger.info(f"预警邮件已发送至: {user_email}，包含 {len(all_domains)} 个{domain_type}")
    except Exception as e:
        logger.exception(f"发送预警邮件失败: {e}")
