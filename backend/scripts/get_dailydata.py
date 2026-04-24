import os
import re
import zipfile
import tempfile
import shutil
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

BASE_URL = "https://www.whoisds.com/newly-registered-domains"

# 与仓库 backend/app/daily_data 一致；容器内为 /app/app/daily_data（与 compose 挂载一致）
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

session = requests.Session()
session.headers.update(HEADERS)


def sanitize_filename(name: str) -> str:
    return re.sub(r'[\\/:*?"<>|]+', "_", name)


def get_latest_download_info():
    resp = session.get(BASE_URL, timeout=30)
    resp.raise_for_status()

    soup = BeautifulSoup(resp.text, "lxml")

    tables = soup.find_all("table")
    target_table = None

    for table in tables:
        header_cells = table.find_all("th")
        header_texts = [th.get_text(" ", strip=True) for th in header_cells]

        if (
            any("Newly Registered Domains List" in x for x in header_texts)
            and any("Download Now" in x for x in header_texts)
            and any("Creation Date" in x for x in header_texts)
        ):
            target_table = table
            break

    if target_table is None:
        raise RuntimeError("未找到目标下载表格")

    rows = target_table.find_all("tr")

    first_row = None
    for row in rows[1:]:
        cols = row.find_all("td")
        a_tag = row.find("a", href=True)
        if len(cols) >= 4 and a_tag:
            first_row = row
            break

    if first_row is None:
        raise RuntimeError("未找到包含下载链接的数据行")

    cols = first_row.find_all("td")

    first_col_text = " ".join(cols[0].stripped_strings)
    match = re.search(r"\d{4}-\d{2}-\d{2}", first_col_text)
    if not match:
        raise RuntimeError(f"无法从第一列提取日期：{first_col_text}")
    display_date = match.group(0)

    count = cols[1].get_text(strip=True)
    creation_date = cols[2].get_text(strip=True)

    a_tag = cols[3].find("a", href=True)
    if a_tag is None:
        raise RuntimeError("该数据行中没有下载链接")

    download_url = urljoin(BASE_URL, a_tag["href"].strip())
    file_name = sanitize_filename(f"{display_date}-domain.zip")

    return file_name, download_url, display_date, creation_date, count


def rename_txt_inside_zip(zip_path, new_txt_name="dailyupdate.txt"):
    """
    将 zip 包内部的 txt 文件重命名为 new_txt_name。
    若 zip 中有多个 txt 文件，则默认重命名第一个 txt 文件。
    其他文件保持不变。
    """
    temp_fd, temp_zip_path = tempfile.mkstemp(suffix=".zip")
    os.close(temp_fd)

    renamed = False

    try:
        with zipfile.ZipFile(zip_path, "r") as zin, zipfile.ZipFile(temp_zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)

                # 只重命名第一个 txt 文件
                if (not renamed) and item.filename.lower().endswith(".txt"):
                    new_item = zipfile.ZipInfo(new_txt_name)
                    new_item.date_time = item.date_time
                    new_item.compress_type = zipfile.ZIP_DEFLATED
                    new_item.comment = item.comment
                    new_item.extra = item.extra
                    new_item.create_system = item.create_system
                    new_item.external_attr = item.external_attr
                    new_item.internal_attr = item.internal_attr

                    zout.writestr(new_item, data)
                    renamed = True
                    print(f"已将压缩包内文件重命名为: {new_txt_name}")
                else:
                    zout.writestr(item, data)

        if not renamed:
            raise RuntimeError("zip 中未找到 .txt 文件，无法重命名")

        shutil.move(temp_zip_path, zip_path)

    except Exception:
        if os.path.exists(temp_zip_path):
            os.remove(temp_zip_path)
        raise


def download_file(file_name, download_url, display_date: str):
    """
    保存到 app/daily_data/<YYYY-MM>/，与 display_date 同月。
    目录不存在则创建；同名文件直接覆盖写入。
    """
    month_key = display_date[:7]
    if len(month_key) != 7 or month_key[4] != "-":
        raise ValueError(f"display_date 需为 YYYY-MM-DD 格式，当前为: {display_date!r}")

    save_dir = os.path.join(DAILY_DATA_ROOT, month_key)
    os.makedirs(save_dir, exist_ok=True)
    file_path = os.path.join(save_dir, file_name)

    if os.path.exists(file_path):
        print("目标已存在，将覆盖:", file_path)
    else:
        print("保存路径:", file_path)

    print("开始下载:", file_name)
    print("下载地址:", download_url)

    with session.get(download_url, stream=True, timeout=60) as r:
        r.raise_for_status()

        with open(file_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)

    print("下载完成:", file_path)

    # 下载后修改 zip 内部 txt 文件名
    rename_txt_inside_zip(file_path, "dailyupdate.txt")

    return file_path


def main():
    print("正在获取最新下载信息...")
    file_name, download_url, display_date, creation_date, count = get_latest_download_info()

    print("最新数据日期:", display_date)
    print("Creation Date:", creation_date)
    print("Count:", count)
    print("保存文件名:", file_name)

    download_file(file_name, download_url, display_date)


if __name__ == "__main__":
    main()