import argparse
import base64
import os
import re
import ssl
import tempfile
import time
import zipfile
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Iterable, List, Optional
from urllib.parse import urljoin
from zoneinfo import ZoneInfo

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter


BASE_URL = "https://www.whoisds.com/newly-registered-domains"
DOWNLOAD_URL_TEMPLATE = (
    "https://www.whoisds.com/whois-database/newly-registered-domains/{token}/nrd"
)
BEIJING_TZ = ZoneInfo("Asia/Shanghai")

# 与仓库 backend/app/daily_data 一致；容器内为 /app/app/daily_data。
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_BACKEND_ROOT = os.path.dirname(_SCRIPT_DIR)
DAILY_DATA_ROOT = os.path.join(_BACKEND_ROOT, "app", "daily_data")

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/147.0.0.0 Safari/537.36 Edg/147.0.0.0"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Referer": "https://www.google.com/",
    "Connection": "keep-alive",
}


class WhoisDsTLSAdapter(HTTPAdapter):
    """仅为 whoisds.com 兼容其弱证书密钥，保留证书链和主机名校验。"""

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        ssl_context = ssl.create_default_context()
        ssl_context.set_ciphers("DEFAULT:@SECLEVEL=1")
        pool_kwargs["ssl_context"] = ssl_context
        return super().init_poolmanager(
            connections,
            maxsize,
            block=block,
            **pool_kwargs,
        )


session = requests.Session()
session.headers.update(HEADERS)
session.mount("https://www.whoisds.com/", WhoisDsTLSAdapter())


@dataclass(frozen=True)
class DownloadInfo:
    file_name: str
    download_url: str
    display_date: str
    creation_date: str = ""
    count: str = ""


class DownloadCutoffReached(RuntimeError):
    """本轮已到自动下载截止时间。"""


def _env_int(name: str, default: int, minimum: int = 1) -> int:
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except (TypeError, ValueError):
        return default


def _beijing_now() -> datetime:
    return datetime.now(BEIJING_TZ)


def _ensure_before_hour(max_start_hour: Optional[int]) -> None:
    if max_start_hour is None:
        return
    if _beijing_now().hour >= max_start_hour:
        raise DownloadCutoffReached(
            f"当前北京时间已达到 {max_start_hour:02d}:00，停止自动下载；不会触发延迟检测或推送"
        )


def sanitize_filename(name: str) -> str:
    return re.sub(r'[\\/:*?"<>|]+', "_", name)


def _request_with_retry(
    url: str,
    *,
    stream: bool = False,
    timeout=(15, 45),
    max_start_hour: Optional[int] = None,
):
    attempts = _env_int("WHOISDS_REQUEST_ATTEMPTS", 3)
    backoff_seconds = _env_int("WHOISDS_RETRY_BACKOFF_SECONDS", 5)
    last_error = None

    for attempt in range(1, attempts + 1):
        _ensure_before_hour(max_start_hour)
        response = None
        try:
            response = session.get(url, stream=stream, timeout=timeout)
            response.raise_for_status()
            return response
        except requests.HTTPError as exc:
            last_error = exc
            status_code = getattr(response, "status_code", None)
            if response is not None:
                response.close()
            # 4xx（429 除外）通常不是瞬时故障，不做无意义重试。
            if status_code is not None and 400 <= status_code < 500 and status_code != 429:
                raise
        except requests.RequestException as exc:
            last_error = exc
            if response is not None:
                response.close()

        if attempt >= attempts:
            break
        sleep_seconds = backoff_seconds * attempt
        print(
            f"请求失败（第 {attempt}/{attempts} 次）: {url}; "
            f"{sleep_seconds} 秒后重试: {last_error}"
        )
        time.sleep(sleep_seconds)

    if last_error is not None:
        raise last_error
    raise RuntimeError(f"请求失败: {url}")


def _find_download_table(soup: BeautifulSoup):
    for table in soup.find_all("table"):
        header_texts = [th.get_text(" ", strip=True) for th in table.find_all("th")]
        if (
            any("Newly Registered Domains List" in value for value in header_texts)
            and any("Download Now" in value for value in header_texts)
            and any("Creation Date" in value for value in header_texts)
        ):
            return table
    raise RuntimeError("未找到目标下载表格")


def _parse_download_infos(html: str) -> List[DownloadInfo]:
    soup = BeautifulSoup(html, "lxml")
    table = _find_download_table(soup)
    infos = []

    for row in table.find_all("tr")[1:]:
        cols = row.find_all("td")
        if len(cols) < 4:
            continue
        link = cols[3].find("a", href=True)
        if link is None:
            continue
        match = re.search(r"\d{4}-\d{2}-\d{2}", " ".join(cols[0].stripped_strings))
        if not match:
            continue
        display_date = match.group(0)
        infos.append(
            DownloadInfo(
                file_name=sanitize_filename(f"{display_date}-domain.zip"),
                download_url=urljoin(BASE_URL, link["href"].strip()),
                display_date=display_date,
                creation_date=cols[2].get_text(strip=True),
                count=cols[1].get_text(strip=True),
            )
        )

    if not infos:
        raise RuntimeError("未找到包含下载链接的数据行")
    return sorted(infos, key=lambda item: item.display_date, reverse=True)


def get_download_infos(max_start_hour: Optional[int] = None) -> List[DownloadInfo]:
    response = _request_with_retry(
        BASE_URL,
        timeout=(15, 30),
        max_start_hour=max_start_hour,
    )
    try:
        return _parse_download_infos(response.text)
    finally:
        response.close()


def get_latest_download_info():
    """保留旧调用接口，返回原有五元组。"""
    info = get_download_infos()[0]
    return (
        info.file_name,
        info.download_url,
        info.display_date,
        info.creation_date,
        info.count,
    )


def _download_url_for_date(target_date: date) -> str:
    token = base64.b64encode(f"{target_date.isoformat()}.zip".encode("ascii")).decode("ascii")
    return DOWNLOAD_URL_TEMPLATE.format(token=token)


def _build_catchup_targets(
    infos: Iterable[DownloadInfo],
    catch_up_days: int,
) -> List[DownloadInfo]:
    infos = list(infos)
    if not infos:
        return []

    by_date = {info.display_date: info for info in infos}
    latest_date = date.fromisoformat(infos[0].display_date)
    targets = []
    for offset in range(catch_up_days - 1, -1, -1):
        target_date = latest_date - timedelta(days=offset)
        display_date = target_date.isoformat()
        targets.append(
            by_date.get(display_date)
            or DownloadInfo(
                file_name=f"{display_date}-domain.zip",
                download_url=_download_url_for_date(target_date),
                display_date=display_date,
            )
        )
    return targets


def _zip_has_dailyupdate(zip_path: str) -> bool:
    if not os.path.isfile(zip_path):
        return False
    try:
        with zipfile.ZipFile(zip_path, "r") as archive:
            return "dailyupdate.txt" in archive.namelist() and archive.testzip() is None
    except (OSError, zipfile.BadZipFile):
        return False


def rename_txt_inside_zip(zip_path, new_txt_name="dailyupdate.txt"):
    """将压缩包内第一个 txt 文件统一命名为 dailyupdate.txt。"""
    temp_fd, temp_zip_path = tempfile.mkstemp(
        suffix=".zip",
        dir=os.path.dirname(os.path.abspath(zip_path)),
    )
    os.close(temp_fd)
    renamed = False

    try:
        with zipfile.ZipFile(zip_path, "r") as source, zipfile.ZipFile(
            temp_zip_path,
            "w",
            compression=zipfile.ZIP_DEFLATED,
        ) as target:
            for item in source.infolist():
                data = source.read(item.filename)
                if not renamed and item.filename.lower().endswith(".txt"):
                    new_item = zipfile.ZipInfo(new_txt_name)
                    new_item.date_time = item.date_time
                    new_item.compress_type = zipfile.ZIP_DEFLATED
                    new_item.comment = item.comment
                    new_item.extra = item.extra
                    new_item.create_system = item.create_system
                    new_item.external_attr = item.external_attr
                    new_item.internal_attr = item.internal_attr
                    target.writestr(new_item, data)
                    renamed = True
                else:
                    target.writestr(item, data)

        if not renamed:
            raise RuntimeError("zip 中未找到 .txt 文件，无法重命名")
        os.replace(temp_zip_path, zip_path)
    except Exception:
        if os.path.exists(temp_zip_path):
            os.remove(temp_zip_path)
        raise


def _target_path(info: DownloadInfo) -> str:
    month_key = info.display_date[:7]
    if len(month_key) != 7 or month_key[4] != "-":
        raise ValueError(f"display_date 需为 YYYY-MM-DD 格式，当前为: {info.display_date!r}")
    return os.path.join(DAILY_DATA_ROOT, month_key, info.file_name)


def download_file(info: DownloadInfo, max_start_hour: Optional[int] = None) -> str:
    """原子下载单日文件；成功校验前不会覆盖现有文件。"""
    file_path = _target_path(info)
    save_dir = os.path.dirname(file_path)
    os.makedirs(save_dir, exist_ok=True)
    temp_fd, temp_path = tempfile.mkstemp(prefix=".whoisds-", suffix=".zip", dir=save_dir)
    os.close(temp_fd)

    print(f"开始下载: {info.file_name}")
    try:
        response = _request_with_retry(
            info.download_url,
            stream=True,
            timeout=(15, 60),
            max_start_hour=max_start_hour,
        )
        try:
            with open(temp_path, "wb") as file_handle:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        file_handle.write(chunk)
        finally:
            response.close()

        rename_txt_inside_zip(temp_path, "dailyupdate.txt")
        if not _zip_has_dailyupdate(temp_path):
            raise RuntimeError(f"下载文件校验失败: {info.file_name}")
        os.replace(temp_path, file_path)
        print(f"下载完成并校验通过: {file_path}")
        return file_path
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def _parse_args(argv=None):
    parser = argparse.ArgumentParser(description="下载并补齐 WhoisDS 每日域名数据")
    parser.add_argument(
        "--catch-up-days",
        type=int,
        default=_env_int("WHOISDS_CATCHUP_DAYS", 14),
        help="从源站最新日期向前检查并补齐的天数，默认 14",
    )
    parser.add_argument(
        "--max-start-hour",
        type=int,
        default=None,
        help="北京时间达到该整点后不再开始网络请求；cron 使用 9",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="只显示计划，不写入文件",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = _parse_args(argv)
    catch_up_days = max(1, args.catch_up_days)

    try:
        _ensure_before_hour(args.max_start_hour)
        print("正在获取最新下载信息...")
        infos = get_download_infos(max_start_hour=args.max_start_hour)
        latest = infos[0]
        print(
            f"源站最新数据: {latest.display_date}; "
            f"Creation Date: {latest.creation_date}; Count: {latest.count}"
        )

        targets = _build_catchup_targets(infos, catch_up_days)
        pending = []
        for info in targets:
            file_path = _target_path(info)
            if _zip_has_dailyupdate(file_path):
                print(f"已存在且校验通过，跳过: {info.display_date}")
            else:
                pending.append(info)

        if not pending:
            print(f"最近 {catch_up_days} 天数据完整，无需下载")
            return 0

        print("待补齐日期:", ", ".join(info.display_date for info in pending))
        if args.dry_run:
            print("dry-run：不写入文件")
            return 0

        failures = []
        for info in pending:
            try:
                _ensure_before_hour(args.max_start_hour)
                download_file(info, max_start_hour=args.max_start_hour)
            except DownloadCutoffReached:
                raise
            except Exception as exc:
                failures.append((info.display_date, str(exc)))
                print(f"补采失败: {info.display_date}: {exc}")

        if failures:
            details = "; ".join(f"{day}: {error}" for day, error in failures)
            raise RuntimeError(f"仍有 {len(failures)} 天补采失败: {details}")
        print(f"补采完成，共新增 {len(pending)} 天数据")
        return 0
    except DownloadCutoffReached as exc:
        print(str(exc))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
