# MSM5xxx Emulator Alpha

Experimental alpha. Qualcomm MSM5000/MSM5100/MSM5500 firmware 실행용 emulator-only 배포본이다.

## 포함과 제외

- firmware는 포함하지 않는다. 사용자가 보유한 dump를 선택한다.
- audio는 이 alpha에서 disabled다.
- optional audio stack, SoundFont (`gm.sf2`), 개발 verify 도구, test, reports는 포함하지 않는다.
- 개발용 corpus, evidence, log, persistent state도 archive에 넣지 않는다.

## 필요 조건

- Python 3.10 이상.
- Tk 포함 Python. Linux는 필요하면 배포판 Tk package를 설치한다
  (`Debian`/`Ubuntu`: `python3-tk`).
- 배포 폴더를 writable location에 푼다.

## 실행

Linux:

```sh
sh ./run_linux.sh "../firmware.bin"
```

Windows:

```bat
run_windows.bat "..\firmware.bin"
```

인자 없이 launcher를 실행하면 firmware 선택 창이 열린다.
두 launcher는 한 번 실행으로 GUI를 시작한다.
필요한 Python dependency가 없을 때만 local virtual environment를 만들고 설치한다.
첫 dependency 설치에는 network access가 필요할 수 있다.
공백이 있는 firmware 경로는 반드시 quote한다.

## 저장 위치

- persistent state 기본 위치: `~/.msm5xxx-emulator/`
- session log 기본 위치: 배포 폴더 `logs/`
- `MSM5XXX_STATE_DIR`, `MSM5XXX_LOG_DIR`로 각각 변경할 수 있다.

firmware 원본은 수정하지 않는다. GUI 종료 뒤에도 state와 log는 남을 수 있다.
세션 log에는 firmware 파일명·bytes·SHA-256, Python/Unicorn/Pillow 버전, 화면·REX·NOR/
EEPROM/NAND telemetry가 남는다. phase/event, 5M instruction checkpoint, terminal에는
`diagnostic-*.json`과 최대 32개의 `frame-*.png`도 남는다. 문제 제보 때 같은 session의
`.log`, `diagnostic-*.json`, `frame-*.png`를 함께 보내면 된다. local firmware 경로는
공유 diagnostic에서 제외한다.

guest fault 또는 Unicorn host backend fault 뒤에는 `repro-.../`도 남는다. 여기에는 path-safe
설정·firmware identity·override 이름·state hash/size와 close 전후 NOR/EEPROM sidecar만 있다.
firmware, last config, NAND raw state는 복사하지 않는다.
NOR/EEPROM sidecar에는 사용자 데이터가 있을 수 있다. `repro-.../`는 공유 전 내용을 확인하고,
공유에 동의한 경우에만 같은 session log와 함께 보낸다.
