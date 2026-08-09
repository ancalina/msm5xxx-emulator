# MSM5xxx QEMU 에뮬레이터

[English](README.md)

QEMU TCG 기반 Qualcomm MSM5000/MSM5100/MSM5500 피처폰 실험용
에뮬레이터입니다. 하드웨어 동작은 모델명이나 파일명이 아니라 펌웨어 내용으로
탐지합니다.

## 다운로드

[Releases](https://github.com/ancalina/msm5xxx-emulator/releases)에서 운영체제용
압축 파일과 `SHA256SUMS`를 받습니다. 압축 전체를 풉니다. Launcher, `bin/`,
동봉 DLL을 분리하지 마십시오.

펌웨어와 저장 state는 포함되지 않습니다.

## 실행

인자 없이 launcher를 실행하면 펌웨어 선택창이 뜹니다.

- Windows: `run_windows.bat`를 더블클릭합니다.
- Linux: `./run_linux.sh`를 실행합니다.
- Intel macOS: `run_macos.command`를 더블클릭하거나 Terminal에서 실행합니다.

Windows에서는 펌웨어 하나를 `run_windows.bat`에 drag-and-drop해도 됩니다.
모든 플랫폼에서 경로를 직접 줄 수도 있습니다.

```sh
./run_linux.sh /path/to/phone.bin
./run_macos.command /path/to/phone.bin
```

```bat
run_windows.bat "C:\path\phone.bin"
```

펌웨어 원본은 읽기 전용입니다.

## 영속 state

재시작 후에도 writable NOR와 EEPROM을 유지하려면 `--state-dir`를 사용합니다.

```sh
./run_linux.sh /path/to/phone.bin --state-dir /path/to/qemu-state
```

Cold boot 후 warm boot가 필요한 경우 같은 directory를 재사용합니다.
`--state-dir`를 생략하면 writable state는 종료 시 폐기됩니다.

## 요구사항

- Tcl/Tk를 포함한 Python 3.10 이상.
- Linux x86-64, Windows x86-64, Intel macOS 15.0 이상.
- Python package 설치가 필요한 첫 실행에서는 network access.

Linux는 `python3-tk`가 필요할 수 있습니다. macOS는
`brew install python-tk@3.14`처럼 Tcl/Tk가 포함된 Python을 설치하십시오.
Windows binary는 unsigned입니다. macOS bundle은 ad-hoc signed이며
notarization되지 않았습니다.

## 현재 호환성

| 펌웨어 | 현재 QEMU 결과 |
|---|---|
| SCH-X350 | 영속 warm boot에서 검증된 idle consumer 도달; END 입력은 input task 도달 |
| KTFT-X3500 | 안정된 standby frame; handset-idle 경로는 미완성 |
| SCH-X250 / X250RUS | Splash와 boot animation; idle은 미완성 |
| SD810 | Upper NOR mapping과 persistence; display/idle은 미완성 |

현재 developer preview입니다. 지원되지 않는 펌웨어는 idle 전에 멈출 수 있습니다.
Detector는 모델명 분기 대신 근거가 불완전한 동작을 fail closed합니다.

## 문제 해결

- Tk 없음: 선택한 Python에 Tcl/Tk support를 설치합니다.
- Dependency 설치 실패: Python `pip`와 network를 확인합니다.
- QEMU 또는 DLL 없음: 압축 전체를 다시 풉니다.
- Nonzero exit: terminal에서 launcher를 실행하고 전체 error text를 보존합니다.

## 개발과 license

Build 방법과 backend 경계는
[docs/QEMU_TCG_BACKEND.md](docs/QEMU_TCG_BACKEND.md)에 있습니다.

프로젝트 license는 `GPL-2.0-or-later`입니다. Binary release에는 QEMU와 동봉
library의 source archive와 notice가 함께 제공됩니다. 제조사 펌웨어는 재배포하지
마십시오.
