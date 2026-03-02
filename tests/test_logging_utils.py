import re

from juicechain.utils.logging import configure_logging, get_logger


def test_logging_file_line_format(tmp_path):
    log_file = tmp_path / "juicechain.log"
    configure_logging(level="CRITICAL", log_file=log_file, enable_file=True)

    logger = get_logger("juicechain.tests.logging")
    logger.info("hello logging")

    root = get_logger("juicechain")
    for h in root.handlers:
        h.flush()

    line = log_file.read_text(encoding="utf-8").strip().splitlines()[-1]
    assert re.match(
        r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \| INFO \| juicechain\.tests\.logging \| hello logging$",
        line,
    )
