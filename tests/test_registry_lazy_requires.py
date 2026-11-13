import importlib
import pkgutil
import unittest


class LazyRequiresTests(unittest.TestCase):
    def test_every_rule_module_resolves_requires_when_imported_directly(self):
        import msm5xxx_emulator.detection.registry  # noqa: F401  installs the resolver
        import msm5xxx_emulator.detection.devices as devices
        missing = []
        for item in pkgutil.walk_packages(devices.__path__, devices.__name__ + "."):
            module = importlib.import_module(item.name)
            missing += [(item.name, name) for name in getattr(module, "REQUIRES", {}) if not hasattr(module, name)]
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()
