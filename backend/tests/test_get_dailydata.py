import importlib.util
import tempfile
import unittest
import zipfile
from datetime import datetime
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "get_dailydata.py"
SPEC = importlib.util.spec_from_file_location("get_dailydata", SCRIPT_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class GetDailyDataTest(unittest.TestCase):
    def test_parse_all_rows_and_sort_descending(self):
        html = """
        <table>
          <tr><th>Newly Registered Domains List</th><th>Count</th><th>Creation Date</th><th>Download Now</th></tr>
          <tr><td>2026-09-15</td><td>70000</td><td>2026-09-16</td><td><a href="/older">download</a></td></tr>
          <tr><td>2026-09-16</td><td>70000</td><td>2026-09-17</td><td><a href="/latest">download</a></td></tr>
        </table>
        """
        infos = MODULE._parse_download_infos(html)
        self.assertEqual([item.display_date for item in infos], ["2026-09-16", "2026-09-15"])
        self.assertTrue(infos[0].download_url.endswith("/latest"))

    def test_catchup_targets_fill_dates_absent_from_page(self):
        latest = MODULE.DownloadInfo(
            file_name="2026-09-16-domain.zip",
            download_url="https://example.invalid/latest",
            display_date="2026-09-16",
        )
        targets = MODULE._build_catchup_targets([latest], 3)
        self.assertEqual(
            [item.display_date for item in targets],
            ["2026-09-14", "2026-09-15", "2026-09-16"],
        )
        self.assertIn("MjAyNi0wOS0xNS56aXA=", targets[1].download_url)

    def test_zip_validation_requires_dailyupdate(self):
        with tempfile.TemporaryDirectory() as directory:
            zip_path = Path(directory) / "sample.zip"
            with zipfile.ZipFile(zip_path, "w") as archive:
                archive.writestr("dailyupdate.txt", "example.com\n")
            self.assertTrue(MODULE._zip_has_dailyupdate(str(zip_path)))

    def test_cutoff_blocks_network_start(self):
        original = MODULE._beijing_now
        try:
            MODULE._beijing_now = lambda: datetime(2026, 9, 17, 9, 0)
            with self.assertRaises(MODULE.DownloadCutoffReached):
                MODULE._ensure_before_hour(9)
        finally:
            MODULE._beijing_now = original


if __name__ == "__main__":
    unittest.main()
