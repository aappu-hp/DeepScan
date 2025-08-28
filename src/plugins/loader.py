# src/plugins/loader.py
import importlib
import pkgutil
import pathlib

from .base import ScannerPlugin

def discover_plugins():
    """Auto-discover all plugins inside the plugins package"""
    plugins = []
    package = __package__ or "src.plugins"   # Ensure correct package path
    package_path = pathlib.Path(__file__).parent

    for _, module_name, ispkg in pkgutil.iter_modules([str(package_path)]):
        if module_name.endswith("_plugin"):
            module = importlib.import_module(f"{package}.{module_name}")
            for attr in dir(module):
                obj = getattr(module, attr)
                if isinstance(obj, type) and issubclass(obj, ScannerPlugin) and obj is not ScannerPlugin:
                    plugins.append(obj())
    return plugins
