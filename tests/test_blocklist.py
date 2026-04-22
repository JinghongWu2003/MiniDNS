from pathlib import Path

from minidns.blocklist import DomainBlocklist


def write_blocklist(path: Path) -> Path:
    path.write_text(
        "\n".join(
            [
                "# comment",
                "",
                "example.com",
                "Ads.Example.org",
            ]
        ),
        encoding="utf-8",
    )
    return path


def test_blocklist_exact_matching(tmp_path):
    blocklist = DomainBlocklist.from_file(write_blocklist(tmp_path / "blocked.txt"))

    assert blocklist.is_blocked("example.com")
    assert blocklist.reason("EXAMPLE.COM.") == "example.com"


def test_blocklist_suffix_matching(tmp_path):
    blocklist = DomainBlocklist.from_file(write_blocklist(tmp_path / "blocked.txt"))

    assert blocklist.is_blocked("ads.example.com")
    assert blocklist.reason("sub.ads.example.org") == "ads.example.org"


def test_blocklist_does_not_match_badexample(tmp_path):
    blocklist = DomainBlocklist.from_file(write_blocklist(tmp_path / "blocked.txt"))

    assert not blocklist.is_blocked("badexample.com")
    assert blocklist.reason("badexample.com") is None
