from __future__ import annotations

from juicechain.core.report import build_scan_report


def _sample_scan_data() -> dict:
    return {
        "meta": {
            "command": "scan",
            "version": "0.6.1.0",
            "timestamp": 1772460000,
        },
        "data": {
            "target": "http://example.test",
            "alive": {
                "alive": True,
                "status_code": 200,
                "response_time_ms": 34,
            },
            "info": {
                "homepage": {
                    "url": "http://example.test/",
                    "status_code": 200,
                },
                "fingerprint": {
                    "server": "nginx",
                    "x_powered_by": "Express",
                    "hints": ["nodejs"],
                },
                "security_headers": {
                    "present": {"X-Frame-Options": "SAMEORIGIN"},
                    "missing": ["Content-Security-Policy"],
                    "deprecated_present": {},
                },
            },
            "enum": {
                "crawler": {
                    "pages_fetched": [{"url": "http://example.test/"}],
                    "spa": {
                        "routes_from_assets": ["/login", "/search"],
                        "api_candidates_from_assets": ["/api/products", "/api/users"],
                    },
                },
                "content_discovery": {
                    "findings_server_endpoints": ["/rest/products"],
                    "findings_spa_routes": ["/#/search"],
                    "findings_fallback_noise": ["/zzzzzz"],
                },
            },
        },
    }


def test_build_scan_report_with_scan_only():
    report = build_scan_report(_sample_scan_data())

    assert "# JuiceChain 安全测试报告" in report
    assert "## 1. 执行概览" in report
    assert "漏洞数据：未提供（仅展示 scan 阶段结果）" in report
    assert "### 2.2 攻击面统计" in report
    assert "## 4. 漏洞详情" not in report


def test_build_scan_report_with_scan_and_vuln():
    scan = _sample_scan_data()
    vuln = {
        "meta": {"command": "vuln"},
        "data": {
            "findings": [
                {
                    "type": "XSS_REFLECTED",
                    "severity": "low",
                    "evidence": "payload reflected",
                    "request": {
                        "url": "http://example.test/search?q=x",
                        "param": "q",
                        "payload": "<script>alert(1)</script>",
                    },
                    "response": {"status_code": 200},
                },
                {
                    "type": "SQLI_ERROR",
                    "severity": "high",
                    "evidence": "sql error in response",
                    "request": {
                        "url": "http://example.test/rest/products/search?q=x",
                        "param": "q",
                        "payload": "' OR '1'='1",
                    },
                    "response": {"status_code": 500},
                },
                {
                    "type": "XSS_DOM",
                    "severity": "medium",
                    "evidence": "dialog captured",
                    "request": {
                        "url": "http://example.test/#/search?q=x",
                        "param": "q",
                        "payload": "<img src=x onerror=alert(1)>",
                    },
                    "response": {"status_code": None},
                },
            ]
        },
    }

    report = build_scan_report(scan, vuln)

    assert "## 3. 漏洞概览" in report
    assert "| 严重级别 | 数量 |" in report
    assert "漏洞统计：严重 0 | 高危 1 | 中危 1 | 低危 1 | 信息 0 | 总计 3" in report
    assert "## 4. 漏洞详情" in report

    high_pos = report.find("SQLI_ERROR")
    medium_pos = report.find("XSS_DOM")
    low_pos = report.find("XSS_REFLECTED")
    assert high_pos != -1 and medium_pos != -1 and low_pos != -1
    assert high_pos < medium_pos < low_pos


def test_build_scan_report_severity_summary_counts():
    scan = _sample_scan_data()
    vuln = {
        "meta": {"command": "vuln"},
        "data": {
            "findings": [
                {"type": "SQLI_ERROR", "severity": "high", "request": {}, "response": {}},
                {"type": "XSS_DOM", "severity": "high", "request": {}, "response": {}},
                {"type": "XSS_REFLECTED", "severity": "medium", "request": {}, "response": {}},
            ]
        },
    }

    report = build_scan_report(scan, vuln)
    assert "漏洞统计：严重 0 | 高危 2 | 中危 1 | 低危 0 | 信息 0 | 总计 3" in report


def test_build_scan_report_recommends_dom_xss_for_spa_without_findings():
    scan = _sample_scan_data()
    vuln = {"meta": {"command": "vuln"}, "data": {"findings": []}}

    report = build_scan_report(scan, vuln)
    assert "--dom-xss" in report
