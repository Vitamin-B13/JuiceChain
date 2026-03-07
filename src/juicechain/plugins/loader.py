from __future__ import annotations

import importlib
import pkgutil

import juicechain.plugins as _pkg
from juicechain.plugins.base import VulnPlugin


def load_all_plugins() -> list[VulnPlugin]:
    plugins: list[VulnPlugin] = []
    for _, module_name, _ in pkgutil.iter_modules(_pkg.__path__):
        if module_name in ("base", "loader"):
            continue
        mod = importlib.import_module(f"juicechain.plugins.{module_name}")
        plugin_cls = getattr(mod, "Plugin", None)
        if plugin_cls is None:
            continue
        plugins.append(plugin_cls())
    return plugins
