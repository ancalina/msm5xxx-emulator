"""Static import-boundary checks for detector device domains."""
import ast
import importlib.util
import os
import subprocess
import sys
import unittest
from pathlib import Path

from msm5xxx_emulator.detection.registry import device_domain, device_domains


SOURCE = Path(__file__).resolve().parents[1] / "src" / "msm5xxx_emulator"
DETECTION = SOURCE / "detection"
DEVICE_DOMAINS = DETECTION / "devices"
DETECTION_PREFIX = "msm5xxx_emulator.detection"
SHARED_DETECTION_MODULES = {
    "arm", "capabilities", "contracts", "facts",
    "firmware_image", "image_view", "layout_facts", "stack_facts",
    "signatures", "startup_entry", "startup_facts", "storage_facts",
    "value_query", "values",
} | {path.stem for pattern in ("startup_*.py", "fact_*.py")
     for path in DETECTION.glob(pattern)} | {
         "function_analysis", "function_states", "function_results",
         "instruction_values", "layout_queries",
     }
SHARED_DETECTION_MODULE_PREFIXES = {
    "fact_", "facts_", "instruction_values", "function_analysis",
}
SHARED_CORE_PREFIXES = {
    "msm5xxx_emulator.core.config",
}
SHARED_FACT_FILES = {
    f"{name}.py" for name in SHARED_DETECTION_MODULES
    if (DETECTION / f"{name}.py").is_file()
} | {path.name for pattern in ("startup_*.py", "fact_*.py")
     for path in DETECTION.glob(pattern)}
SHARED_FACT_FILE_PREFIXES = {
    "fact_", "facts_", "instruction_values", "function_analysis",
}


def module_name(path):
    relative = path.relative_to(SOURCE).with_suffix("")
    parts = relative.parts
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(("msm5xxx_emulator", *parts))


def module_exists(module, available_modules=None):
    if available_modules is not None:
        return module in available_modules
    relative = Path(*module.split("."))
    return ((SOURCE / relative).with_suffix(".py").is_file()
            or (SOURCE / relative / "__init__.py").is_file())


def imported_modules(path, tree, available_modules=None):
    current = module_name(path)
    package = current if path.name == "__init__.py" else current.rpartition(".")[0]
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name, node.lineno
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                relative = "." * node.level + (node.module or "")
                target = importlib.util.resolve_name(relative, package)
            else:
                target = node.module or ""
            if target:
                yield target, node.lineno
                for alias in node.names:
                    candidate = f"{target}.{alias.name}"
                    if module_exists(candidate, available_modules):
                        yield candidate, node.lineno


def is_detection_devices(module):
    return (module == f"{DETECTION_PREFIX}.devices"
            or module.startswith(f"{DETECTION_PREFIX}.devices."))


def domain_for(path):
    relative = path.relative_to(DEVICE_DOMAINS)
    return relative.parts[0] if relative.parts else None


def shared_layer_import_problem(imported):
    if imported == DETECTION_PREFIX + '.plan' or imported.startswith(DETECTION_PREFIX + '.plan.'):
        return 'shared facts cannot depend on the consuming plan'
    if is_detection_devices(imported):
        return "shared facts layers cannot depend on device domains"
    if imported == f"{DETECTION_PREFIX}.registry":
        return "shared facts layers cannot depend on the device registry"
    if imported.startswith(DETECTION_PREFIX + ".") and not is_shared_detection_module(imported):
        return "shared facts layers cannot depend on legacy detector modules"
    return None


def is_shared_detection_module(imported):
    shared = {f"{DETECTION_PREFIX}.{name}" for name in SHARED_DETECTION_MODULES}
    if any(imported == prefix or imported.startswith(prefix + ".")
           for prefix in shared):
        return True
    if not imported.startswith(DETECTION_PREFIX + "."):
        return False
    name = imported[len(DETECTION_PREFIX) + 1:].split(".", 1)[0]
    return any(name.startswith(prefix)
               for prefix in SHARED_DETECTION_MODULE_PREFIXES)


def domain_import_problem(imported, own_prefix):
    if imported == own_prefix or imported.startswith(own_prefix + "."):
        return None
    if is_shared_detection_module(imported):
        return None
    if any(imported == prefix or imported.startswith(prefix + ".")
           for prefix in SHARED_CORE_PREFIXES):
        return None
    if imported.startswith(("msm5xxx_emulator.qemu", "msm5xxx_emulator.devices", "msm5xxx_emulator.gui")):
        return "device admission cannot depend on runtime consumers"
    if is_detection_devices(imported):
        return f"device domains cannot import sibling domain {imported}"
    if imported.startswith(DETECTION_PREFIX + "."):
        return f"device domains cannot import legacy detector module {imported}"
    return None


class DeviceImportTests(unittest.TestCase):
    def test_lazy_projection_composes_its_own_helper_dependencies(self):
        program = """
from types import SimpleNamespace
from msm5xxx_emulator.detection.registry import device_domain
projection = device_domain('storage.transport_projection')
image = bytes(8)
config = SimpleNamespace(flash_size=0x100000, ram_base=0x1800000, ram_size=0x800000)
value, reason = projection.qemu_sharp_board_status_property(image, image, config, claimed=False)
assert value is None and reason.startswith('sharp-board-status-lcd-source-unverified:')
"""
        subprocess.run([sys.executable, '-c', program], check=True,
                       env={**os.environ, 'PYTHONPATH': str(SOURCE.parent),
                            'PYTHONDONTWRITEBYTECODE': '1'}, capture_output=True, text=True)

    def test_registry_discovers_packages_and_rejects_unknown_domains(self):
        domains = device_domains()
        self.assertIsInstance(domains, tuple)
        self.assertEqual(domains, tuple(sorted(set(domains))))
        with self.assertRaises(KeyError):
            device_domain("missing-domain")

    def test_shared_facts_layers_do_not_import_device_domains_or_registry(self):
        filenames = set(SHARED_FACT_FILES)
        for prefix in SHARED_FACT_FILE_PREFIXES:
            filenames.update(path.name for path in DETECTION.glob(prefix + "*.py"))
        for filename in sorted(filenames):
            path = DETECTION / filename
            self.assertLessEqual(len(path.read_text().splitlines()), 600,
                                 f"{path} exceeds shared-module limit")
            tree = ast.parse(path.read_text(), filename=str(path))
            for imported, line in imported_modules(path, tree):
                problem = shared_layer_import_problem(imported)
                self.assertIsNone(problem, f"{path}:{line}: {imported}: {problem}")

    def test_detection_consumers_use_registry_instead_of_direct_domain_imports(self):
        registry_path = DETECTION / "registry.py"
        for path in SOURCE.rglob("*.py"):
            if path.is_relative_to(DEVICE_DOMAINS) or path == registry_path:
                continue
            tree = ast.parse(path.read_text(), filename=str(path))
            for imported, line in imported_modules(path, tree):
                self.assertFalse(is_detection_devices(imported), f"{path}:{line}: {imported}")

    def test_plan_contains_no_literal_device_signatures(self):
        for path in (DETECTION / 'plan').rglob('*.py'):
            for node in ast.walk(ast.parse(path.read_text())):
                if isinstance(node, ast.Constant) and isinstance(node.value, bytes):
                    self.assertLessEqual(len(node.value), 1, f'{path}:{node.lineno}')
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    self.assertNotEqual(node.func.attr, 'fromhex', f'{path}:{node.lineno}')

    def test_display_consumers_request_only_display_providers(self):
        for path in (SOURCE / 'devices' / 'display').rglob('*.py'):
            for node in ast.walk(ast.parse(path.read_text())):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                        and node.func.id == 'device_domain' and node.args
                        and isinstance(node.args[0], ast.Constant)):
                    self.assertTrue(node.args[0].value.startswith('display.'), f'{path}:{node.lineno}')

    def test_domain_imports_stay_within_domain_or_shared_layers(self):
        for path in DEVICE_DOMAINS.rglob("*.py"):
            domain = domain_for(path)
            if domain is None or path.name == "__init__.py" and path.parent == DEVICE_DOMAINS:
                continue
            self.assertLessEqual(len(path.read_text().splitlines()), 600, str(path))
            tree = ast.parse(path.read_text(), filename=str(path))
            own_prefix = f"{DETECTION_PREFIX}.devices.{domain}"
            for imported, line in imported_modules(path, tree):
                if imported == own_prefix or imported.startswith(own_prefix + "."):
                    continue
                problem = domain_import_problem(imported, own_prefix)
                self.assertIsNone(problem, f"{path}:{line}: {imported}: {problem}")

    def test_every_discovered_rule_has_bound_evidence_requirements(self):
        for path in sorted(DEVICE_DOMAINS.rglob("*.py")):
            relative = path.relative_to(DEVICE_DOMAINS).with_suffix("")
            parts = relative.parts[:-1] if path.name == "__init__.py" else relative.parts
            if not parts:
                continue
            module = device_domain(".".join(parts))
            for symbol, (provider, attribute) in getattr(module, "REQUIRES", {}).items():
                if provider.split('.')[0] != parts[0] and attribute is not None:
                    self.assertFalse(attribute.startswith('_'), f'{module.__name__}: private provider {provider}.{attribute}')
                dependency = device_domain(provider)
                expected = dependency if attribute is None else getattr(dependency, attribute)
                self.assertIs(getattr(module, symbol), expected, f"{module.__name__}.{symbol}")

    def test_root_contains_only_shared_layers_and_registry(self):
        allowed = SHARED_DETECTION_MODULES | {"__init__", "registry"}
        for path in DETECTION.glob("*.py"):
            self.assertTrue(path.stem in allowed or any(path.stem.startswith(prefix)
                            for prefix in SHARED_FACT_FILE_PREFIXES), str(path))
        for name in SHARED_DETECTION_MODULES | {'plan'}:
            package = DETECTION / name
            if not package.is_dir():
                continue
            for path in package.rglob("*.py"):
                self.assertLessEqual(len(path.read_text().splitlines()), 600, str(path))
                if name != 'plan':
                    for imported, line in imported_modules(path, ast.parse(path.read_text())):
                        self.assertIsNone(shared_layer_import_problem(imported), f"{path}:{line}: {imported}")

    def test_synthetic_ast_imports_enforce_each_direction(self):
        domain_path = DEVICE_DOMAINS / "sample" / "__init__.py"
        domain_tree = ast.parse(
            "from . import helper\n"
            "from ...facts import FirmwareFacts\n"
            "from .. import sibling\n"
            "from ... import boot_page\n"
        )
        available = {
            f"{DETECTION_PREFIX}.devices.sample.helper",
            f"{DETECTION_PREFIX}.devices.sibling",
            f"{DETECTION_PREFIX}.boot_page",
        }
        found = list(imported_modules(domain_path, domain_tree, available))
        own = f"{DETECTION_PREFIX}.devices.sample"
        facts = f"{DETECTION_PREFIX}.facts"
        sibling = f"{DETECTION_PREFIX}.devices.sibling"
        legacy = f"{DETECTION_PREFIX}.boot_page"
        self.assertIn((f"{own}.helper", 1), found)
        self.assertIn((facts, 2), found)
        self.assertIn((sibling, 3), found)
        self.assertIn((legacy, 4), found)
        self.assertIsNone(domain_import_problem(f"{own}.helper", own))
        self.assertIsNone(domain_import_problem(facts, own))
        self.assertIsNone(domain_import_problem(
            f"{DETECTION_PREFIX}.startup_loops", own))
        self.assertIsNone(domain_import_problem(
            f"{DETECTION_PREFIX}.fact_values", own))
        self.assertIsNone(domain_import_problem(
            f"{DETECTION_PREFIX}.facts_functions", own))
        self.assertIsNone(domain_import_problem(
            f"{DETECTION_PREFIX}.instruction_values", own))
        self.assertIsNone(domain_import_problem(
            f"{DETECTION_PREFIX}.function_analysis", own))
        self.assertIsNotNone(domain_import_problem("msm5xxx_emulator.qemu.decoder", own))
        self.assertIsNotNone(domain_import_problem("msm5xxx_emulator.devices.input", own))
        self.assertIn("sibling", domain_import_problem(sibling, own))
        self.assertIn("legacy", domain_import_problem(legacy, own))

        shared_tree = ast.parse("from . import registry\n")
        shared_import = list(imported_modules(DETECTION / "facts.py", shared_tree,
                                              {f"{DETECTION_PREFIX}.registry"}))
        registry = f"{DETECTION_PREFIX}.registry"
        self.assertIn((registry, 1), shared_import)
        self.assertIsNotNone(shared_layer_import_problem(registry))
        self.assertIsNone(shared_layer_import_problem(f"{DETECTION_PREFIX}.facts"))
        self.assertIsNotNone(shared_layer_import_problem(
            f"{DETECTION_PREFIX}.input"))

        consumer_tree = ast.parse("from . import devices\nfrom . import registry\n")
        consumer_imports = list(imported_modules(
            DETECTION / "consumer.py", consumer_tree,
            {f"{DETECTION_PREFIX}.devices", registry}))
        self.assertIn((f"{DETECTION_PREFIX}.devices", 1), consumer_imports)
        self.assertIn((registry, 2), consumer_imports)
        self.assertTrue(is_detection_devices(f"{DETECTION_PREFIX}.devices"))
        self.assertFalse(is_detection_devices(registry))


if __name__ == "__main__":
    unittest.main()
