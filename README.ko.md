# MSM5xxx 에뮬레이터: 실험적 QEMU TCG backend

[English](README.md)

Qualcomm MSM5000/MSM5100/MSM5500 펌웨어 실행을 QEMU TCG로 옮기는
브랜치입니다. 재현 가능한 emulator 개발용 source checkpoint이며, 아직 일반
사용자용 alpha package는 아닙니다.

Unicorn 구현은 동작 oracle로 tree에 보존됩니다. Root의 `run_linux.sh`와
`run_windows.bat`는 기존 Unicorn frontend를 실행하며 이 QEMU backend를
시작하지 않습니다.

## 현재 상태

`handset idle`은 식별된 firmware idle consumer와 이를 뒷받침하는 task/frame
근거가 있어야 합니다. 화면이나 QEMU process가 살아 있다는 사실만으로는 pass가
아닙니다.

| 펌웨어 | QEMU에서 검증됨 | 남은 gap |
|---|---|---|
| SCH-X350 | Cold storage 초기화 후 같은 state로 warm boot하면 UISIdle `0xC125C -> 0xC1308` 도달; 이후 20M guest instruction 동안 REX/LCD 진행; physical END `0x51` press/release가 input task 도달 | UI power-off effect, reset parity, release packaging |
| KTFT-X3500 | Detector가 승인한 DC0 battery profile로 guest state 주입 없이 안정된 128x160 standby frame 도달 | Current module은 module0B에 머묾; module1/idle consumer 미폐쇄 |
| SD810 | Detector가 승인한 `0x02800000`의 8 MiB upper x8 NOR mapping/read/persistence | Periodic IRQ producer/cadence/acknowledge 미해결; completed frame 없음 |
| SCH-X250 | Anycall splash와 animation | Idle entry 미도달 |
| SCH-X250RUS | Anycall splash와 animation | Early-device RX status/data/frame/CRC contract 미해결; fatal loop `0x1608` 진입 |

아직 release pass인 행은 없습니다. 고정 5종 alpha gate도 충족하지 못했습니다.

END event `0x51`은 matrix event table에 없다는 이유만으로 거부하지 않습니다.
유일한 physical sideband producer와 consumer path가 검출된 경우에만
활성화합니다. Producer가 없거나 duplicated/ambiguous/collision이면 기존처럼
fail closed합니다.

## Backend 경계

- QEMU가 deterministic instruction-counted time으로 ARMv4T 펌웨어를 실행합니다.
- Native C가 device/MMIO hot path, IRQ, LCD, storage, matrix input과 현재 승인된
  protocol class를 처리합니다.
- Python은 firmware 구조를 검출하고 승인된 machine property만 전달하며,
  completed LCD write decode와 실험적 GUI를 담당합니다.
- Model명이나 firmware filename이 아니라 signature, call shape, consumer,
  runtime readback으로 탐지합니다.
- 불완전한 detector는 native fallback을 유지하거나 reject reason을 남깁니다.
  Boot를 진행시키려고 알 수 없는 hardware 값을 만들지 않습니다.

정확한 device, determinism, reset, release 경계는
[QEMU backend 문서](docs/QEMU_TCG_BACKEND.md)를 확인하십시오.

## 빌드

검증한 target은 QEMU `v10.2.1`의 `arm-softmmu`이며 Python 3.10+와 Tk가
필요합니다. 이 브랜치를 clone하고 machine source를 QEMU source tree에 복사한
뒤 `hw/arm/meson.build`에 등록합니다.

```sh
git clone --branch engine/qemu-tcg-alpha-20260809 \
  https://github.com/ancalina/msm5xxx-emulator.git
cp msm5xxx-emulator/experiments/qemu-tcg/msm5xxx-poc.c \
  /path/to/qemu/hw/arm/
```

```meson
arm_common_ss.add(files('msm5xxx-poc.c'))
```

[docs/QEMU_TCG_BACKEND.md](docs/QEMU_TCG_BACKEND.md#build-and-run)의 명령으로
QEMU를 configure/build합니다.

## 실행

```sh
cd msm5xxx-emulator
PYTHONPATH=src python3 experiments/qemu-tcg/live-display.py FIRMWARE \
  --qemu /path/to/qemu-system-arm --state-dir /path/to/qemu-state
```

펌웨어 원본은 읽기 전용입니다. NOR/EEPROM 변경은 별도 state directory에
기록됩니다. Cold storage 초기화 후 persistent warm boot가 필요한 펌웨어는 같은
directory를 재사용하십시오. `--state-dir`를 생략하면 종료 시 폐기되는 state를
만듭니다.

## 검증

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_*.py' -v
```

공개한 checkpoint는 test 380개 통과, corpus-dependent skip 10개와 native
`qemu-system-arm` build를 통과했습니다.

## 배포와 라이선스

이 repository에는 제조사 펌웨어, 사용자 state, evidence, diagnostic log,
screenshot, IDA database가 없습니다. Source 또는 binary archive에도 넣지
마십시오.

프로젝트 license는 `GPL-2.0-or-later`입니다. QEMU binary를 배포할 때는 해당
license가 요구하는 corresponding source와 notice도 함께 제공해야 합니다.
[LICENSE](LICENSE)와 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)를
확인하십시오.
