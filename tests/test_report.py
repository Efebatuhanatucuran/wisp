from pathlib import Path

from wisp import report


def test_mask_home_path_replaces_username():
    home = Path.home()
    masked = report.mask_home_path(home / "Library" / "foo.json")
    assert str(home) not in masked
    assert masked.endswith("Library/foo.json")
    assert "****" in masked


def test_mask_home_path_leaves_other_paths_untouched():
    assert report.mask_home_path("/tmp/somewhere/x.json") == "/tmp/somewhere/x.json"


def test_mask_home_path_handles_bare_home_dir():
    home = Path.home()
    masked = report.mask_home_path(home)
    assert masked.endswith("****")
    assert str(home) != masked
