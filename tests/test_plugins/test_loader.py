from juicechain.plugins.loader import load_all_plugins


def test_loader_discovers_plugins():
    plugins = load_all_plugins()
    assert len(plugins) >= 7
    assert all(getattr(plugin, "name", "") for plugin in plugins)
    assert all(getattr(plugin, "severity", "") for plugin in plugins)
