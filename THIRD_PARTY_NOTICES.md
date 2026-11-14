# Third-party notices

The project is GPL-2.0-or-later; the combined QEMU distribution selects the
GPLv2 option. Components retain their own licenses and copyright notices. The
component source locations and build inputs below do not replace corresponding
source and license texts accompanying a binary distribution. See
[source distribution](docs/SOURCE_DISTRIBUTION.md) and the individual source
archives for license texts, notices, modifications and build recipes.

## QEMU and native libraries

- **QEMU 10.2.1**, patched for this project, is GPL-2.0-only for the system
  emulator, with LGPL-2.1 components and other notices in its source. It is
  used on desktop, Android and iOS. Upstream source is
  [QEMU 10.2.1](https://download.qemu.org/qemu-10.2.1.tar.xz); project patches
  and staging instructions are in [native/qemu](native/qemu/README.md).
- **DTC/libfdt** is dual licensed GPL-2.0-only or BSD-2-Clause. The QEMU build
  uses the pinned [DTC source](https://gitlab.com/qemu-project/dtc.git); see
  `native/qemu/qemu_build_inputs.env` for the revision.
- **GLib** is LGPL-2.1-or-later. Android and iOS build 2.88.1; desktop builds
  use their platform libraries. Source inputs and recipes are recorded in
  `android/build_glib_android.sh`, `ios/build_glib_ios.sh` and
  `native/qemu/build_qemu_native.sh`.
- **PCRE2** is BSD-3-Clause; **libffi** uses an MIT-style license; and
  **proxy-libintl** is LGPL-2.0-or-later. Android and iOS GLib builds use
  PCRE2 10.46, libffi 3.4.4 and proxy-libintl 0.5. The iOS interpreter also
  links libffi. Their source archives and recipes are identified by the GLib
  build scripts above. Desktop dependency versions depend on the bundle.

## Python and Python packages

- **CPython** uses the Python Software Foundation License and contains additional
  third-party components under their own licenses; see its `LICENSE` and
  `Doc/license.rst`. The Android runtime embeds CPython 3.14.4 and its libffi;
  its preparation and source inputs are in `android/prepare_runtime.sh`. The
  iOS bundle uses BeeWare's CPython 3.14.10 iOS support distribution and its
  native dependencies; the pinned distribution and build instructions are in
  [iOS Python instructions](ios/PYTHON.md). Desktop uses the user's Python.
- **NumPy** is BSD-3-Clause, with additional notices for bundled components.
  Android includes 2.5.1, built from the source archive identified by
  `android/build_numpy_android.sh`; desktop installs `numpy>=1.26,<3`.
  iOS does not bundle NumPy.
- **Capstone** is BSD-3-Clause. Android and iOS bundle Capstone 5.0.7, built
  from the source archive identified by `android/build_capstone_android.sh` and
  `ios/build_capstone_ios.sh`; desktop installs `capstone>=5,<6`.
- **Pillow** (`Pillow>=10,<13`) uses the MIT-CMU License. It is a desktop
  Python dependency installed by the launcher, not a mobile bundled package. Its
  requirements are recorded in `requirements.txt`; retain package notices and
  any notices for their own native dependencies.

## Platform-specific components

- **Windows:** the build collects the MinGW DLL dependency closure. The pinned
  package list in `native/qemu/windows_dependency_sources.json` identifies
  GLib, PCRE2, gettext runtime (GPL-3.0-or-later and LGPL-2.1-or-later package
  metadata), libiconv (GPL-3.0-or-later package metadata, with library notices),
  winpthreads (MIT and BSD-3-Clause) and zlib (Zlib). Source archive locations
  and license files are recorded there. The build writes `DLLS.txt`,
  `MSYS2_PACKAGES.txt` and `licenses/msys2/` for the actual bundle; use those
  records for any changed dependency closure.
- **Android:** the NumPy build includes the Android NDK C++ shared runtime;
  its NDK notice is copied into the app's license assets by
  `android/prepare_runtime.sh`. Android framework APIs are provided by the
  operating system. The app uses Google Material Icons, Apache-2.0.
- **iOS:** the app embeds QEMU, QEMUTCI, CPython and CPython extension
  frameworks; the session extension embeds QEMUTCI. Apple frameworks including
  SwiftUI, UIKit, Foundation, AVFoundation and ExtensionFoundation are system
  frameworks, subject to Apple's platform terms. The GLib build also links
  CoreFoundation and Foundation. See `ios/build_python_ios.sh`,
  `ios/build_qemu_ios.sh` and the Xcode project for the build inputs.

## App icon

The icon marking (`branding/chip_icon.py`) is drawn with the Hershey Sans
1-stroke font, converted to paths:

- The Hershey Fonts were originally created by Dr. A. V. Hershey while working
  at the U. S. National Bureau of Standards.
- The format of the Font data in this distribution was originally created by
  James Hurt, Cognition, Inc., 900 Technology Park Drive, Billerica, MA 01821
  (mit-eddie!ci-dandelion!hurt).

TODO: Check the final iOS Python support archive's bundled native dependency
licenses and ensure their complete notices and corresponding source accompany
the iOS release. Verify the final platform artifacts against their actual
bundled dependency manifests and include all applicable license texts.
