# MSM5xxx 에뮬레이터

[English](README.md)

Unicorn 기반 Qualcomm MSM5000/MSM5100/MSM5500 피처폰 펌웨어 에뮬레이터입니다.

문서화되지 않은 구형 모바일 하드웨어의 보존과 재현 가능한 연구를 목적으로 하는
실험적 프로젝트입니다. 제조사 펌웨어, 사용자 상태, 로그, 스크린샷은 포함하지
않습니다. 오디오 자산은 검수된 GPL-2.0-only TimGM6mb SoundFont 하나만
포함합니다.

별도 빌드 과정 없이 소스를 clone하거나 압축 해제한 뒤 플랫폼 launcher를
실행하면 됩니다.

## 실행

요구 사항:

- Python 3.10 이상
- Tk
- Git 또는 다운로드한 소스 archive

Linux:

```sh
git clone https://github.com/ancalina/msm5xxx-emulator.git
cd msm5xxx-emulator
sh ./run_linux.sh /path/to/firmware.bin
```

Windows:

```bat
git clone https://github.com/ancalina/msm5xxx-emulator.git
cd msm5xxx-emulator
run_windows.bat C:\path\to\firmware.bin
```

처음 실행할 때 `.venv`를 만들고 `unicorn`, `Pillow`, `NumPy`를 설치할 수
있습니다.

단일 runtime 증거만 있는 C80 timer/IRQ profile은 opt-in입니다.

```text
--experimental-c80-controller
```

## 프로젝트 상태

현재 활발히 개발 중이며 아직 완전한 단말 에뮬레이션을 제공하지 않습니다.

현재 연구 범위:

- ARM 펌웨어 실행
- 펌웨어 구조 기반 메모리 및 장치 탐지
- 화면과 keypad emulation
- 영구 NOR, EEPROM, NAND 상태
- REX, timer, IRQ, storage 연구
- 실험적 Yamaha MA-2 및 MA-5 처리
- 재현 가능한 진단과 호환성 추적

장치 탐지는 제조사, 모델명, KEYEMUL, 펌웨어 파일명에 의존하지 않습니다.
불완전하거나 모호한 경로는 비활성화하거나 native fallback을 유지합니다.

## 펌웨어와 상태

펌웨어 원본은 읽기 전용으로 처리합니다. 영구 상태의 기본 위치는 다음과 같습니다.

```text
~/.msm5xxx-emulator/
```

상태와 로그 위치는 다음 환경 변수로 변경할 수 있습니다.

```text
MSM5XXX_STATE_DIR
MSM5XXX_LOG_DIR
```

지원 입력 형식:

- raw binary
- strict Intel HEX (`.hex`)
- HXB (`.hxb`)

HXB는 유효한 일치 HEX member가 하나만 있을 때 memory에서 decode합니다.
Embedded loader는 실행하지 않습니다.

진단 report는 확장 가능한 JSON schema와 로컬 경로가 제거된 SHA-256 source
식별자를 사용합니다.

## Storage

필요한 펌웨어 구조가 검출되면 NOR, secondary NOR, EEPROM, NAND 상태를
별도로 영속 저장할 수 있습니다.

NAND dump는 대응하는 NOR 펌웨어와 별도로 연결해야 합니다.

```sh
python msm5xxx.py phone-nor.bin --nand-image phone-nand.bin \
  --nand-data-size 0x1000000 --nand-page-size 512 --nand-spare-size 16 \
  --nand-pages-per-block 32 --nand-bus-width 2
```

원본 dump는 읽기 전용이며 변경 사항은 별도 저장됩니다. 알 수 없는 NAND
geometry를 추측하지 말고 지원을 요청할 때 정확한 file size와 진단 log를 함께
제출하십시오.

## Keypad 입력

지원되는 firmware matrix와 queue 경로가 검출된 경우에만 자동 keypad 입력을
활성화합니다.

알 수 없는 transport, 모호한 cell, 지원되지 않는 multi-key 경로는 비활성으로
유지합니다.

GUI 버튼을 우클릭하면 펌웨어별 수동 event-byte mapping을 설정할 수 있습니다.
이때 queue에 event를 직접 주입하지 않고 검출된 physical row와 column을
펌웨어의 정상 scanner 경로로 입력합니다.

## 실험적 오디오

펌웨어의 audio driver는 그대로 실행됩니다.

현재 상태:

- MA-2: 근사 MMF/PCM rendering
- MA-5: write telemetry만 지원
- MA-3: 비활성

MA-2 FIFO snapshot과 유효한 MMF buffer는 번들 TimGM6mb SoundFont로
render할 수 있습니다. 출력은 근사치이며 실제 Yamaha hardware와 같음을
보장하지 않습니다.

재생은 `ffplay`, 그다음 Windows `winsound`를 사용합니다. 둘 다 없으면
render-only로 동작합니다. 오디오 실패는 guest emulation을 중단하지 않습니다.

## 업데이트

GUI에서 GitHub `main`의 업데이트를 확인할 수 있습니다.

업데이트는 사용자 확인 후 검증된 manifest 소유 runtime file만 교체합니다.
펌웨어와 관련 없는 파일은 수정하지 않으며, offline 또는 확인 실패가 emulation에
영향을 주지 않습니다.

## 에뮬레이터 개선 참여

### 호환성 상태

[커뮤니티 호환성 시트](docs/COMMUNITY_COMPATIBILITY_SHEET.md)에서 모델, 칩셋,
화면, 입력, 부팅, runtime 상태를 기록할 수 있습니다.

### 테스트 로그 제출

1. 에뮬레이터를 실행합니다.
2. 생성된 `logs/` directory를 `logs.zip`으로 압축합니다.
3. [테스트 로그 제출 양식](https://forms.gle/8ThEtrJgZceiAE3HA)으로 보냅니다.
4. 기대 동작과 실제 결과를 함께 적습니다.

Ancalina에게 archive를 직접 전달해도 됩니다.


## 패키지 설치

Source checkout이 기본 배포 방식이며 local package 설치도 지원합니다.

```sh
python3 -m pip install .
msm5xxx-emulator /path/to/firmware.bin --detect-only
msm5xxx-boot-probe /path/to/firmware.bin
```

기존 source 실행 명령도 계속 지원합니다.

```text
python msm5xxx.py
python boot_probe.py
python gui.py
run_linux.sh
run_windows.bat
```

## 개발

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 -m py_compile _compat.py msm5xxx.py gui.py boot_probe.py
python3 -m py_compile $(find src -name '*.py' -print)
```

대부분의 test는 synthetic byte sequence를 사용합니다. Corpus 의존 test에는
private local `firmwares/` directory가 필요합니다.

제조사 펌웨어, 사용자 상태, 진단 bundle, screenshot, 검수되지 않은 SoundFont,
local path를 repository에 추가하지 마십시오.

## 라이선스

Copyright © 2026 Ancalina.

`GPL-2.0-or-later`로 배포됩니다.

Unicorn은 `GPL-2.0-only`입니다. Unicorn을 포함하거나 결합한 배포판은 이
프로젝트의 GPLv2 option을 사용해야 하며 GPLv3-only 또는 AGPL code를 포함해서는
안 됩니다.

[`LICENSE`](LICENSE)와
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)를 확인하십시오.
