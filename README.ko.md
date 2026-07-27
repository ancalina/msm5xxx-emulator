# MSM5xxx 에뮬레이터

[English](README.md)

Unicorn 기반 Qualcomm MSM5000/MSM5100/MSM5500 피처폰 펌웨어 에뮬레이터입니다.
실험적 프로젝트입니다.
이 소스에는 펌웨어, 사용자 상태, 로그, 스크린샷, 오디오 asset이 없습니다.
별도 빌드 과정은 필요 없습니다. GitHub 소스 archive를 압축 해제하고 아래
플랫폼 launcher를 실행하면 됩니다.

## 실행

Python 3.10 이상과 Tk가 필요합니다.

```sh
sh ./run_linux.sh /path/to/firmware.bin
```

```bat
run_windows.bat C:\path\to\firmware.bin
```

launcher를 처음 실행하면 `.venv`를 만들고 `unicorn`과 `Pillow`를 설치할 수
있습니다. 펌웨어 원본은 읽기 전용입니다. 영구 NOR/EEPROM/NAND 상태는 기본적으로
`~/.msm5xxx-emulator/`에 저장됩니다. 위치를 바꾸려면 `MSM5XXX_STATE_DIR`과
`MSM5XXX_LOG_DIR`을 설정하십시오. 인식된 legacy GEFS seed mismatch가 발생하면
기존 영구 MSM5000 secondary NOR state를 제자리에서 재사용하며 data와 path를
보존합니다. 진단 JSON은 확장 가능한 `schema: 1`을 사용합니다.
`runtime.sources`에는 CLI, GUI, boot probe, runtime logger module의 로컬 경로
없는 SHA-256 식별자가 기록됩니다.

Raw binary, strict Intel HEX (`.hex`), HXB (`.hxb`)를 직접 선택할 수 있습니다.
HXB는 archive stem과 같은 top-level HEX member가 정확히 하나일 때만 memory에서
decode합니다. Embedded loader를 실행하거나 파일을 추출하지 않으며 checksum,
EOF, address, overlap, size가 잘못되면 거부합니다.

펌웨어의 relocatable catalog, address materializer, translator, native AMD
writer, caller grammar가 모두 닫히면 `0x02800000..0x02FFFFFF`에 독립 8 MiB
NOR를 mapping합니다. 상태는 별도로 영속 저장하며 이 범위는 LCD traffic으로
decode하지 않습니다. 불완전하거나 ambiguous한 일치는 native fallback을 유지하고
reject 이유를 기록합니다. 이 storage 판정만으로 handset idle을 주장하지 않습니다.

자동 keypad 입력은 exact direct 6x4 matrix와 Samsung ring32 또는 LG ring256
queue sink가 닫힌 경우 활성화됩니다. LG descriptor 6x5 경로도 legacy 5 ms
timer, detector-closed two- 또는 three-bank controller route, IRQ wrapper,
handler slot, queue drain이 모두 닫힌 경우 활성화됩니다. Three-bank
pending/status access는 검증된 IRQ handler 안으로 제한됩니다. 모델명·파일명별
규칙은 쓰지 않습니다. LG class는 숫자 key, `*`, `#`를 검증된 matrix 위치에
mapping합니다. Samsung ring32는 `MENU`, `UP/DOWN/LEFT/RIGHT`, 취소, 통화도
mapping합니다. 남은 single-key GUI control은 firmware table 순서의 미사용
unique/non-filler cell에 deterministic experimental mapping합니다. 실제 key
의미와 다를 수 있으며 test log로 physical cell의 동작을 수집하기 위한
best-effort 기능입니다. 미검출 transport, ambiguous cell, multi-key 입력은
계속 비활성입니다.

모든 버튼은 우클릭으로 event byte를 override할 수 있습니다. 사용할 수 있는
자동 cell이 없는 버튼을 누르면 같은 편집창이 열립니다. `0x53` 같은 값은
검출된 firmware matrix table에 정확히 한 번 있을 때만 허용하며 `0x00`,
`0xFF`, matrix no-key 값은 거절합니다. 그 row와 column을 정상
scanner/debounce 경로로 누르며 firmware queue에 byte를 직접 주입하지
않습니다. Mapping은 firmware SHA-256별로 저장되고 빈 값으로 삭제합니다.

모든 accepted/rejected edge는 requested source, mapping source
(`automatic-evidenced`, `automatic-experimental`, `manual`), rule, reason을
기록합니다. Accepted edge는 detector family/fingerprint, firmware event,
row/column, fallback rank, scanner/queue/task counter도 기록합니다. 수동
mapping 편집은 accept/reject 결정과 정리된 requested value를 남깁니다. 이를
이용해 experimental label 오탐과 transport 실패를 구분합니다.

Descriptor 입력 telemetry는 scanner-to-enqueue call edge와 실제 raw-ring store,
dequeue return, task receipt를 구분합니다. SV130과 SD810 After의 fresh 숫자키
press/release는 fault 없이 네 단계를 모두 통과했습니다. 이는 firmware task 전달
증명이며 visible UI 반응, handset idle, `OK` semantic 증명은 아닙니다.

### 업데이트

GUI는 백그라운드에서 GitHub `main`을 확인합니다. 현재 설치에서 아직 확인하지
않은 commit이 있으면 다운로드 전에 묻습니다. 수락하면 검증된 복사본을
`~/.msm5xxx-emulator/updates/`에 받은 뒤, 압축 해제된 폴더에서 manifest 소유
runtime file만 교체하고 GUI를 다시 시작합니다. 펌웨어와 manifest 외부 file은
건드리지 않습니다. 수정된 배포 source를 교체할 때는 별도 확인을 요구합니다.
거절하면 해당 commit만 다시 묻지 않으며, 이후 새 commit은 다시 알립니다.
실패하거나 offline이면 조용히 건너뛰며 emulation에 영향을 주지 않습니다.

### 별도 NAND dump 연결

NAND dump는 data이며 boot firmware가 아닙니다. 대응하는 NOR dump를 실행하고
NAND를 별도로 연결하십시오. 512-byte page마다 16-byte spare가 붙은 16 MiB main
data의 RIFF 형식 raw dump 예시는 다음과 같습니다.

```sh
python msm5xxx.py phone-nor.bin --nand-image phone-nand.bin \
  --nand-data-size 0x1000000 --nand-page-size 512 --nand-spare-size 16 \
  --nand-pages-per-block 32 --nand-bus-width 2
```

이 main+spare interleaved layout은 `0x1080000` byte
(`32768 × (512 + 16)`)입니다. 입력 dump는 읽기 전용이며 영구 NAND 변경은
별도로 저장됩니다. 다른 geometry를 추측하지 말고 log와 file size를 제출하십시오.

## 에뮬레이터 개선 참여

### 커뮤니티 펌웨어 상태표

[커뮤니티 호환성 시트](docs/COMMUNITY_COMPATIBILITY_SHEET.md)에서
펌웨어 모델, 칩셋, 화면, 입력, 부팅, runtime 상태를 기록할 수 있습니다.
시트 URL 변경은 이 문서 한 곳에서만 수정합니다.

### 테스트 로그 제출

1. 펌웨어로 에뮬레이터를 실행합니다.
2. 생성된 `logs/` directory를 `logs.zip`으로 압축해
   [테스트 로그 제출 양식](https://forms.gle/8ThEtrJgZceiAE3HA)으로 보냅니다.
3. 누른 GUI 버튼, 기대 동작, firmware에서 실제 발생한 동작을 함께 적습니다.

...또는 Ancalina를 찾아 archive를 직접 보내도 됩니다.

CLI JSON은 mapping된 NOR data를 바꾸지 않고 완료된 primary NOR 직접
`0x90`, `+0/+2`, `0xFF` ID probe를 기록합니다. 캡처된 word는 dump byte이며
실제 physical ID라고 주장하지 않습니다.

terminal 진단은 최근 unmapped access 16개를 PC, address, size, value, outcome과
함께 보존합니다. 이는 device evidence를 기록할 뿐, device response를 추론하거나
알 수 없는 hardware를 mapping하지 않습니다.

## 패키지 설치

```sh
python3 -m pip install .
msm5xxx-emulator /path/to/firmware.bin --detect-only
msm5xxx-boot-probe /path/to/firmware.bin
```

기존 source checkout 명령도 계속 지원합니다: `python msm5xxx.py`,
`python boot_probe.py`, `python gui.py`, `run_linux.sh`, `run_windows.bat`.

## 개발

```sh
python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 -m py_compile _compat.py msm5xxx.py gui.py boot_probe.py
python3 -m py_compile $(find src -name '*.py' -print)
```

대부분의 test는 synthetic byte sequence를 사용합니다. private local
`firmwares/` directory가 없으면 corpus 의존 regression은 skip됩니다. 제조사
firmware, 사용자 상태, 진단 bundle, screenshot, SoundFont, local path를 추가하지
마십시오.

## 라이선스

Copyright © 2026 Ancalina. `GPL-2.0-or-later`로 배포됩니다.

Unicorn은 GPLv2-only입니다. Unicorn을 포함하거나 결합한 에뮬레이터 배포판은 이
프로젝트의 GPLv2 option을 사용해야 합니다. GPLv3-only 또는 AGPL code와 결합하지
마십시오. `LICENSE`와 `THIRD_PARTY_NOTICES.md`를 확인하십시오.
