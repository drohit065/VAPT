"""Every backend and worker module must at least import (catches syntax errors in untested code)."""
import importlib

import pytest

MODULES = ["app.main", "app.routers.auth", "app.routers.projects", "app.routers.scans",
           "app.worker.pipeline", "app.worker.fetch", "app.worker.detect", "app.worker.dast",
           "app.pdf_report", "app.normalize", "app.security"]


@pytest.mark.parametrize("name", MODULES)
def test_module_imports(name):
    importlib.import_module(name)
