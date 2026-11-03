"""Exercise native build option selection without compiling QEMU."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


class TCIBuildOptionsTests(unittest.TestCase):
    def test_ios_modes_pass_expected_configure_options(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as name:
            temp = Path(name)
            ios = temp / "ios"
            native = temp / "native/qemu"
            ios.mkdir()
            native.mkdir(parents=True)
            shutil.copy(root / "ios/build_qemu_ios.sh", ios)
            (native / "qemu_build_inputs.env").write_text(
                "MSM5XXX_IOS_PATCH_SHA256=expected\n")
            (native / "qemu-10.2.1-ios-host.patch").write_text("")
            stage = native / "stage_qemu_source.sh"
            stage.write_text('''#!/bin/sh
mkdir -p "$2/subprojects"
cat > "$2/configure" <<'CONFIGURE'
#!/bin/sh
printf '%s\\n' "$@" > configure-args
CONFIGURE
chmod +x "$2/configure"
''')
            stage.chmod(0o755)
            tools = temp / "tools"
            tools.mkdir()
            for tool, body in {
                "xcrun": "case \"$3\" in --find) command -v cc ;; *) echo / ;; esac",
                "shasum": "echo expected",
                "patch": "exit 0",
                "tar": "exit 0",
                "ninja": "exit 0",
                "file": "exit 0",
            }.items():
                path = tools / tool
                path.write_text(f"#!/bin/sh\n{body}\n")
                path.chmod(0o755)
            env = dict(os.environ, PATH=f"{tools}:{os.environ['PATH']}")
            for mode in ("tcg", "tci"):
                with self.subTest(mode=mode):
                    work = temp / f"work-{mode}"
                    subprocess.run([str(ios / "build_qemu_ios.sh"), "iphoneos",
                                    "arm64", mode, "archive", "dtc", "glib",
                                    str(work)], env=env, check=True,
                                   capture_output=True, text=True)
                    args = (work / "build/configure-args").read_text().splitlines()
                    self.assertEqual("--enable-tcg-interpreter" in args, mode == "tci")
                    cflags = next(a for a in args if a.startswith("--extra-cflags="))
                    self.assertEqual("-O3" in cflags.split(), mode == "tci")

    def test_native_modes_pass_expected_configure_options(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            scripts = temp / "scripts"
            scripts.mkdir()
            shutil.copy(root / "native/qemu/build_qemu_native.sh", scripts)
            (scripts / "qemu_build_inputs.env").write_text(
                "QEMU_VERSION=10.2.1\nQEMU_DTC_REVISION=revision\n")
            stage = scripts / "stage_qemu_source.sh"
            stage.write_text('''#!/bin/sh
mkdir -p "$2/subprojects"
cat > "$2/configure" <<'CONFIGURE'
#!/bin/sh
printf '%s\\n' "$@" > configure-args
cat > qemu-system-arm <<'QEMU'
#!/bin/sh
case "$1" in
  --version) echo 'QEMU emulator version 10.2.1' ;;
  -machine) echo 'msm5xxx-poc synthetic' ;;
esac
QEMU
chmod +x qemu-system-arm
CONFIGURE
chmod +x "$2/configure"
''')
            stage.chmod(0o755)
            tools = temp / "tools"
            tools.mkdir()
            git = tools / "git"
            git.write_text('''#!/bin/sh
case "$3" in
  rev-parse) echo revision ;;
  archive) tar -cf - --files-from /dev/null ;;
esac
''')
            git.chmod(0o755)
            ninja = tools / "ninja"
            ninja.write_text("#!/bin/sh\nexit 0\n")
            ninja.chmod(0o755)
            dtc = temp / "dtc"
            (dtc / ".git").mkdir(parents=True)
            for mode in ("0", "1"):
                with self.subTest(interpreter=mode):
                    env = dict(os.environ, PATH=f"{tools}:{os.environ['PATH']}",
                               MSM5XXX_DTC_SOURCE=str(dtc),
                               MSM5XXX_TCG_INTERPRETER=mode)
                    work = temp / f"work-{mode}"
                    subprocess.run([str(scripts / "build_qemu_native.sh"),
                                    "unused-archive", str(work)],
                                   env=env, check=True, capture_output=True,
                                   text=True)
                    args = (work / "build/configure-args").read_text().splitlines()
                    self.assertEqual("--enable-tcg-interpreter" in args, mode == "1")
                    cflags = next(a for a in args if a.startswith("--extra-cflags="))
                    self.assertEqual("-O3" in cflags.split(), mode == "1")


if __name__ == "__main__":
    unittest.main()
