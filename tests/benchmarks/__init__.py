"""Benchmarks, kept out of the ordinary suite by --ignore=tests/benchmarks.

They live under tests/ so that `ruff check exeradar tests` reaches them — the
same arrangement apkradar, mailradar and cookieradar use — and the runner they
need, pytest-codspeed, is installed by codspeed.yml alone. A suite that checks
whether the code is correct on four Python versions has no business depending
on a benchmark tool.
"""
