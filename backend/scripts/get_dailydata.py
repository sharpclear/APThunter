import os
from bs4 import BeautifulSoup
import cloudscraper
import random
import time

# 全局 scraper
scraper = cloudscraper.create_scraper()

# 目标网页
BASE_URL = "https://www.whoisextractor.in/domains-database/daily-free/"

# 保存根目录：相对本脚本，对应 backend/app/daily_data/
# 实际路径为 SAVE_DIR/{YYYY-MM}/文件名.zip，月份与文件名日期一致。订阅任务九点执行，爬取文件应在此之前，如8点。
SAVE_DIR = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "app", "daily_data")
)


def _month_folder_from_zip_filename(file_name: str) -> str:
    """从文件名解析月份文件夹名，如 2026-03-15-domain.zip -> 2026-03"""
    base = file_name[:-4] if file_name.lower().endswith(".zip") else file_name
    parts = base.split("-")
    if len(parts) >= 2 and len(parts[0]) == 4 and parts[0].isdigit() and len(parts[1]) == 2 and parts[1].isdigit():
        return f"{parts[0]}-{parts[1]}"
    raise ValueError(f"无法从文件名解析月份目录: {file_name!r}")

# 请求头
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Cookie": """_ga=GA1.1.1680713414.1773629889; _fbp=fb.1.1773629888716.374548781186603005; g_state={"i_l":0,"i_ll":1773630215367,"i_b":"YFm44dSmMdYmzXWhQIOGkYo9EBaGnj503x0WSn6z9pM","i_e":{"enable_itp_optimization":0}}; WHMCSlogin_auth_tk=SWF3ZVQ1ZkQ4bTFyOEs0RDdaZmEwTmMrMlJjR21aUlpvaUY1blBVS3JRZ0hURHRMN0hWeUVtV2NZUGdUSjFpUDc1Wkd3b29BQUR4QVpjYTZjT2NYZkRqbnBYM1Bub3lCZ1ZwdnB3R1FHQlFKdnNPOFh2UnFxZlUrRmJvVjNOaWg3aUptTWxPZVV0QXhOVkEyOGVYYXFzUlhBVklpaDJhZ0ZvMUpHSlpSRHJNNTJ1TDQ3RzNhMHNzcHQ0QnYwdnhRaVJVK1o2cEhKank2cGVWQ3RDaXNhY1BvRzcwRmx3UldmYnEvdXNuQnFWSFZnYTRxYzNHSmw3R1lhWjN5WGxtYlQ3Mmo3TmdjQ2ZKcXEvRGwxVXlSN1FRTExWRmRqcG10cXRaMmJHS2RPOGowUVVkOWxobVB5WThrM0YrdFNoZFdocjg4cHFJMWtIWUR1a2FFc2h2ZHdOZTN0SWczVktSQmM1L1psTXRuRVFIVGRjNGwzM3NMZnRFS0o2SnQzeGtHcmZJU3NIUXdtdmVWbGNOSyszb2gzREFNMURvZlN5TUlzdzBlN01Sb25hUWNDdFFNMVZNQks5cz0%3D; WHMCSxjLcDnvnTBrK=joirfm60cccsmqv292ht74gh8c; PHPSESSID=p9g011iu9vaskb2ndh8sg3o1ak; _ga_R8BHTFHRQY=GS2.1.s1773654294$o2$g1$t1773655108$j60$l0$h487086474; cf_clearance=UIhFVZN3F3Q1cRSP5iNRA7KdaMYFv7UBMNOjIc0iGTc-1773655109-1.2.1.1-nNIUvBbexwWaNB.aR8l1VIH73xLlMTg1nzuaaL6oBtdyXykaT.Y8afeEJurNqIrWcgD7620bxW0g.MnhJVP7.WdHeE8D9CSsVaBVKD6_rLrisFNiP8oYbDaW_QUTmh1LojXVHmzK.i16lyRt8gF1CBqJL_jxoYN6ZQT6unyvNbYp5CtPXTKX75R6Txhl2E0_8Qk8FoonsQ1LQSegKKi7NTHaQhhTJ7NPVteQ41g0.FU; __gads=ID=84047fb539200e28:T=1773629891:RT=1773655109:S=ALNI_MbGxWSs5UYfU0DY5BWMrHcoG5vTGA; __gpi=UID=0000121f9230395b:T=1773629891:RT=1773655109:S=ALNI_Ma867kOjSbQyWJhk-cgUKgaNfOD4w; __eoi=ID=2189614f14b5857f:T=1773629891:RT=1773655109:S=AA-AfjYeEpSDRpabmCaKIFgafFdd; FCCDCF=%5Bnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2C%5B%5B32%2C%22%5B%5C%2286420729-495f-4391-948b-9940bb4d6092%5C%22%2C%5B1773629894%2C997000000%5D%5D%22%5D%5D%5D; FCNEC=%5B%5B%22AKsRol_VWqpbC5uoqKgQPVWoIGQYXQOAmBTXYXAUK5RJJS-OkHAdF52Huj1uA8kHXMC_Mbe4E8mewJikYTCrdDUgiY80erKAM5nCMpYcHvSRiVhQf2HdP7gHcLL7OV8bLMvtzDH5fFDxCgVnXBJo0zgf7tZyaMAn5A%3D%3D%22%5D%5D""",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Referer": "https://www.google.com/",
    "Connection": "keep-alive"
}

# 随即延迟函数
def random_delay(max_seconds=360):
    delay = random.randint(0, max_seconds)
    print(f"[随机延迟] 等待 {delay} 秒（约 {delay/60:.1f} 分钟）")
    time.sleep(delay)

def get_latest_download_info():
    """
    获取最新一天的下载信息
    返回:
        file_name  例如: 2026-03-15-domain.zip
        file_id    例如: 4e902ce536dec0daef8a9cb6e4e80839
    """

    resp = scraper.get(BASE_URL, headers=HEADERS)
    resp.raise_for_status()

    soup = BeautifulSoup(resp.text, "html.parser")

    table = soup.find("table", {"id": "databaseHistoryTable"})
    tbody = table.find("tbody")

    first_row = tbody.find("tr")

    a = first_row.find("a", href=True)

    file_name = a.text.strip()
    href = a["href"]

    # 提取 id
    file_id = href.split("id=")[-1]

    return file_name, file_id


def download_file(file_name, file_id):

    # 构造真实下载地址
    real_url = f"https://www.whoisextractor.in/get/?id={file_id}"

    month_dir = os.path.join(SAVE_DIR, _month_folder_from_zip_filename(file_name))
    os.makedirs(month_dir, exist_ok=True)
    file_path = os.path.join(month_dir, file_name)

    if os.path.exists(file_path):
        print("文件已存在:", file_name)
        return

    print("开始下载:", file_name)
    print("下载地址:", real_url)

    r = scraper.get(real_url, headers=HEADERS, stream=True)
    r.raise_for_status()

    with open(file_path, "wb") as f:
        for chunk in r.iter_content(8192):
            if chunk:
                f.write(chunk)

    print("下载完成:", file_path)


def main():

    os.makedirs(SAVE_DIR, exist_ok=True)

    random_delay(360) #增加随机延迟
    print("正在获取最新下载信息...")

    file_name, file_id = get_latest_download_info()

    print("最新文件:", file_name)
    print("文件ID:", file_id)

    download_file(file_name, file_id)


if __name__ == "__main__":
    main()