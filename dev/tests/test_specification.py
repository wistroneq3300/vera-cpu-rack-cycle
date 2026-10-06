"""Offline contract tests for the formal validation specification."""
from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path

from cycle_engine import new_record
from cycle_report import render_html, write_reports
from cycle_specification import ITEMS, render_specification, write_specification


ROOT = Path(__file__).resolve().parents[2]


class SpecificationTests(unittest.TestCase):
    def test_specification_generates(self):
        with tempfile.TemporaryDirectory() as temp:
            path = write_specification(temp)
            self.assertTrue(path.is_file())
            self.assertIn("Vera Cycle Validation Specification", path.read_text(encoding="utf-8"))

    def test_uses_repository_logo_asset_without_redrawing_it(self):
        source = (ROOT / "wistron-logo.svg").read_text(encoding="utf-8")
        page = render_specification()
        self.assertIn('viewBox="-1.18218396 -1.18218396 214.57440792 41.77049992"', source)
        self.assertIn('viewBox="-1.18218396 -1.18218396 214.57440792 41.77049992"', page)
        self.assertIn("#9acd66", page)
        self.assertIn("#016c8c", page)
        self.assertEqual(page.count('<span class="brand-mark"'), 2)

    def test_html_is_self_contained_and_offline(self):
        page = render_specification()
        self.assertNotIn("<link ", page.lower())
        self.assertNotIn("<script src=", page.lower())
        self.assertNotIn("<img ", page.lower())
        self.assertNotIn("https://", page.lower())
        self.assertNotIn("cdn.", page.lower())
        self.assertIn("<style>", page)
        self.assertIn("<script>", page)

    def test_bilingual_default_and_language_switch_contract(self):
        page = render_specification()
        self.assertIn('<html lang="zh-TW" data-lang="zh-TW">', page)
        self.assertIn('body data-lang="zh-TW"', page)
        self.assertIn('data-lang-button="zh-TW"', page)
        self.assertIn('data-lang-button="en"', page)
        self.assertIn("document.documentElement.lang=lang", page)
        self.assertIn("setLanguage('zh-TW')", page)
        self.assertIn("Validation Methodology, Execution Flow, Pass/Fail Criteria and Evidence Definition", page)
        self.assertIn("驗證方法、執行流程、通過／失敗判定準則與證據定義", page)

    def test_all_required_sections_and_sop_fields_exist(self):
        page = render_specification()
        for section_id in (
            "overview", "flow", "matrix", "pre-check", "cycle-execution", "post-check",
            "kernel-hardware", "bmc-logs", "project-interface", "semantics", "traceability", "integrity",
        ):
            self.assertIn(f'id="{section_id}"', page)
        self.assertEqual(page.count('class="matrix-entry"'), len(ITEMS))
        for label in (
            "Purpose", "Phase", "Command or Data Source", "Collection Method", "Validation Logic",
            "PASS Criteria", "WARN Criteria", "FAIL Criteria", "Retry / Confirmation Logic",
            "PRE ↔ POST Comparison", "Evidence", "Issue Code", "Notes",
        ):
            self.assertIn(label, page)
        for value in ("PASS", "WARN", "FAIL", "KNOWN", "NEW", "COMPLETE", "INCOMPLETE"):
            self.assertIn(value, page)

    def test_specification_stays_project_independent_and_formal(self):
        page = render_specification()
        lowered = page.lower()
        forbidden = (
            "neutrino", "naboo", "cpu_min", "dimm_expected", "nvme_min", "nic_min",
            "bf4_expected", "pciefab_min", "usb_min", "bmc_min", "demo", "sample",
            "ai generated", "chatgpt", "codex", "openhands",
        )
        for word in forbidden:
            self.assertNotIn(word, lowered, word)
        self.assertNotIn("expected at least 2", lowered)
        self.assertNotIn("expected exactly 16", lowered)
        self.assertIn("Project-Specific Hardware Validation Interface", page)
        self.assertIn("CHECK|...", page)
        self.assertIn("ISSUE|code|component|reason", page)
        self.assertIn("RESULT|PASS", page)
        self.assertIn("RESULT|FAIL", page)

    def test_print_styles_and_relative_links(self):
        page = render_specification()
        self.assertIn("@page{size:A4 portrait", page)
        self.assertIn("@media print", page)
        self.assertIn('href="CYCLE_REVIEW_REPORT.html"', page)
        self.assertNotIn('href="/CYCLE_REVIEW_REPORT.html"', page)
        self.assertNotIn('href="file:', page.lower())

    def test_report_integration_writes_both_documents_and_links_back(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            pre = new_record("PRE")
            pre.update(status="PASS", finished="2026-10-06T10:00:00+08:00")
            node = dict(
                key="tray-node", target={"os_ip": "192.0.2.10", "bmc_ip": "192.0.2.11"}, blocked=[],
                active=True, pre=pre, loops=[], completed=0, attempts=0, boot_confirmed=0,
                valid_cycles=0, stop_reason="", stage="",
            )
            campaign = dict(
                run_id="offline_spec", state="COMPLETE", project="generic", started="2026-10-06T09:00:00+08:00",
                finished="2026-10-06T10:00:00+08:00", stop_reason="Requested run limit reached",
                cycle_mode="power_cycle", channel="inband", limits={"loops": 1, "hours": 0},
                script_sha256="0" * 64, nodes=[node],
            )
            write_reports(root, campaign)
            report = (root / "CYCLE_REVIEW_REPORT.html").read_text(encoding="utf-8")
            spec = (root / "CYCLE_VALIDATION_SPECIFICATION.html").read_text(encoding="utf-8")
            self.assertIn('href="CYCLE_VALIDATION_SPECIFICATION.html"', report)
            self.assertIn('href="CYCLE_REVIEW_REPORT.html"', spec)
            self.assertTrue((root / "campaign.json").is_file())


if __name__ == "__main__":
    unittest.main()
