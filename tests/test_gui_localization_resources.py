import json
from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]


class LocalizationResourcesTest(unittest.TestCase):
    def test_desktop_locales_and_python_sources(self):
        directory = ROOT / 'src/msm5xxx_emulator/gui'
        en = json.loads((directory / 'locales/en.json').read_text(encoding='utf-8'))
        ko = json.loads((directory / 'locales/ko.json').read_text(encoding='utf-8'))
        self.assertEqual(en.keys(), ko.keys())
        for path in directory.rglob('*.py'):
            self.assertNotRegex(path.read_text(encoding='utf-8'), r'[가-힣]', str(path))
        self.assertIn('locales/*.json', (ROOT / 'pyproject.toml').read_text())

    def test_android_resource_names_and_key_descriptions(self):
        res = ROOT / 'android/app/src/main/res'
        def names(path):
            root = ET.parse(path).getroot()
            return {(item.tag, item.attrib['name']) for item in root}
        self.assertEqual(names(res / 'values/strings.xml'), names(res / 'values-ko/strings.xml'))
        source = (ROOT / 'android/app/src/main/java/org/msm5xxx/emulator/MainActivity.java').read_text()
        key_names = re.findall(r'new KeySpec\(R\.string\.(key_\w+)', source)
        self.assertEqual(len(key_names), 23)
        resources = names(res / 'values/strings.xml')
        for name in key_names:
            self.assertIn(('string', name), resources)
        self.assertIn('target.setContentDescription(spokenKeyLabel(key))', source)
        self.assertIn('default: return getString(key.labelResource)', source)
        self.assertNotRegex(source, r'\.(?:setText|setHint|setTitle|setMessage|setContentDescription)\("[^"\n]+"')

    def test_ios_tables_and_project_registration(self):
        base = ROOT / 'ios/app/MSM5xEmu'
        def table(language):
            result = {}
            for line in (base / (language + '.lproj') / 'Localizable.strings').read_text().splitlines():
                match = re.fullmatch(r'("(?:[^"\\]|\\.)*")\s*=\s*("(?:[^"\\]|\\.)*");', line)
                self.assertIsNotNone(match, line)
                key, value = map(json.loads, match.groups())
                self.assertNotIn(key, result)
                result[key] = value
            return result
        self.assertEqual(table('en').keys(), table('ko').keys())
        project = (ROOT / 'ios/app/MSM5xEmu.xcodeproj/project.pbxproj').read_text()
        self.assertIn('isa = PBXVariantGroup', project)
        self.assertIn('Localizable.strings in Resources', project)
        self.assertIn('FirmwareLibrary.swift in Sources', project)
        self.assertRegex(project, r'knownRegions\s*=\s*\([^)]*\bko\b')
