# MSM5xxx QEMU 에뮬레이터 0.2.0

[English](README.md)

Qualcomm MSM5000, MSM5100, MSM5105, MSM5500 칩셋을 사용하는 피처폰을 보존하고
살펴보기 위한 실험적인 QEMU 기반 에뮬레이터입니다. 호환성은 펌웨어마다 다르며,
지원 칩셋이라고 해서 부팅을 보장하지는 않습니다.

**직접 덤프한 펌웨어를 사용하세요.** 펌웨어와 저장 상태는 포함되어 있지 않습니다.

## 기능

- 탐지된 하드웨어가 지원하는 경우 메인 및 보조 디스플레이.
- 화면 키패드와 측면 키, 호스트 키보드 입력 및 편집 가능한 입력 매핑.
- 톤 생성기와 지원되는 Yamaha 오디오 하드웨어를 포함한 오디오 에뮬레이션.
- 선택 가능한 가상 네트워크와 네트워크 시간 설정. 실제 이동통신망에 연결하지는 않습니다.
- 쓰기 가능한 장치 상태의 저장과 기기별 설정을 제공하는 펌웨어 라이브러리.
- Windows, macOS, Linux용 네이티브 데스크톱 앱. 라이트/다크 테마, 한국어와 영어,
  앱 내 업데이트를 지원합니다.

## 설치와 실행

[Releases](https://github.com/ancalina/msm5xxx-emulator/releases)에서 플랫폼에 맞는
패키지를 받습니다. 라이브러리에서 직접 덤프한 펌웨어를 가져오거나 선택한 후 실행합니다.
데스크톱 패키지에는 필요한 구성요소가 모두 들어 있어 Python을 따로 설치하지 않아도 됩니다.

- **Windows 10 (1809) 이상, x86-64:** `MSM5xxx-win-Setup.exe`를 실행합니다. 현재
  사용자용으로 설치되고 시작 메뉴에 추가됩니다. 설치 파일은 서명되지 않아 "Windows의
  PC 보호" 창이 뜨면 **추가 정보 → 실행**을 누릅니다. 업데이트는 앱에서 안내합니다.
  [Windows 안내](desktop/windows/README.md)를 참고하세요.
- **Intel macOS 15 이상:** DMG를 열고 앱을 응용 프로그램 폴더로 끌어 놓습니다. 앱은
  공증되지 않았으므로 처음 실행할 때 앱을 우클릭해 **열기**를 선택하거나
  **시스템 설정 → 개인정보 보호 및 보안**에서 허용합니다. 업데이트는 앱에서 안내합니다.
  [macOS 안내](desktop/macos/README.md)를 참고하세요.
- **Linux x86-64 (glibc 2.43 이상, 예: Ubuntu 26.04):** AppImage에 실행 권한을 주고
  실행하거나 패키지 관리자로 `.deb`를 설치합니다. FUSE가 없으면
  `APPIMAGE_EXTRACT_AND_RUN=1`로 AppImage를 실행합니다. AppImage는 앱에서 스스로
  업데이트합니다. [Linux 안내](desktop/linux/README.md)를 참고하세요.
- **Android 9 이상, arm64:** APK를 설치하고 앱을 열어 시스템 파일 선택기로
  덤프를 가져옵니다. 앱이 업데이트를 확인하며, 이전 버전 위에 데이터를 유지한 채 설치됩니다.
- **iOS 15 이상:** 적절하게 서명하고 프로비저닝한 IPA를 설치하거나 TrollStore로
  TIPA를 설치합니다. 앱을 열어 덤프를 가져옵니다. IPA는 인터프리터를 사용하며,
  TIPA는 가능한 경우 디버거를 이용한 JIT를 사용할 수 있습니다.
  [iOS 안내](ios/README.md)를 참고하세요.

쓰기 가능한 NOR 및 EEPROM 상태는 펌웨어별로 별도 저장되며 원본 덤프는 읽기
전용입니다. 데스크톱 앱은 라이브러리, 설정, 상태를 사용자별 데이터 폴더(Windows
`%LOCALAPPDATA%\MSM5xxx`, macOS `Application Support/MSM5xxx`, Linux
`~/.local/share/msm5xxx`)에 보관하며, 제거해도 유지됩니다. 모바일 앱은 앱 저장 공간을 사용합니다.

## 알려진 제한

- 일부 펌웨어는 로고에서 멈추거나 화면을 표시하지 않으며 작동하는 기능은 기기마다
  다릅니다. [호환성 시트](docs/COMMUNITY_COMPATIBILITY_SHEET.md)를 참고하세요.
- iOS에서 Stop은 현재 기기를 대기 상태로 둡니다. Start로 같은 펌웨어를
  초기화하여 재개할 수 있습니다. 펌웨어를 바꾸거나 중지된 세션이 재개되지 않으면
  앱을 다시 여세요. 일부 설정도 앱을 다시 열어야 적용됩니다.
- Android 보조 디스플레이는 사용 가능한 Presentation 디스플레이를 이용할 수 있습니다.
  Android가 노출하지 않는 커버 화면 대신 앱 안에 표시합니다.

빌드 정보와 라이선스는 [QEMU 백엔드](docs/QEMU_TCG_BACKEND.md),
[서드파티 고지](THIRD_PARTY_NOTICES.md), [소스 배포](docs/SOURCE_DISTRIBUTION.md)를
참고하세요. 프로젝트는 GPL-2.0-or-later이며 동봉 구성요소에는 각자의 라이선스가 적용됩니다.
