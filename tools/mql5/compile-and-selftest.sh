#!/usr/bin/env bash
# Compile the MQL5 sources with MetaEditor under Wine, then run the generated
# self-test (Scripts/VeritasChain/VCP_SelfTest.mq5) in the MetaTrader 5 terminal.
#
# Linux only. Needs wine (Wine 11 or later; see mql5/README.md), curl, iconv,
# and Xvfb when no X display is available. osslsigncode, if installed, is used to
# check that the downloaded installer is signed by MetaQuotes Ltd.
#
# The first run downloads the MetaTrader 5 installer from MetaQuotes
# (download.mql5.com), which then downloads the terminal. Nothing is logged in
# and no trading account is used. MT5_WORK (default: .mt5 in the repository,
# ignored by git) holds the Wine prefix and the download.
#
# Exit status: 0 if both files compile with 0 errors and 0 warnings and the
# self-test reports "0 failed"; 1 otherwise; 3 if the tools are missing.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="${MT5_WORK:-$ROOT/.mt5}"
export WINEPREFIX="$WORK/prefix" WINEARCH=win64 WINEDEBUG=-all
export WINEDLLOVERRIDES="mscoree,mshtml="   # skip the Wine Mono and Gecko prompts

for tool in wine wineserver curl iconv; do
  command -v "$tool" >/dev/null || { echo "$tool not found" >&2; exit 3; }
done

XVFB=""
cleanup() {
  wineserver -k 2>/dev/null || true
  [ -n "$XVFB" ] && kill "$XVFB" 2>/dev/null || true
}
trap cleanup EXIT
if [ -z "${DISPLAY:-}" ]; then
  command -v Xvfb >/dev/null || { echo "no DISPLAY and Xvfb not found" >&2; exit 3; }
  Xvfb :97 -screen 0 1280x960x24 >/dev/null 2>&1 &
  XVFB=$!
  export DISPLAY=:97
  sleep 2
fi

utf8() { iconv -f UTF-16LE -t UTF-8 "$1" | tr -d '\r' | sed 's/^\xEF\xBB\xBF//'; }

T="$WINEPREFIX/drive_c/Program Files/MetaTrader 5"
if [ ! -f "$T/MetaEditor64.exe" ]; then
  mkdir -p "$WORK/dl"
  [ -d "$WINEPREFIX" ] || wineboot -i >/dev/null 2>&1
  curl -fsSL -o "$WORK/dl/mt5setup.exe" \
    https://download.mql5.com/cdn/web/metaquotes.software.corp/mt5/mt5setup.exe
  if command -v osslsigncode >/dev/null; then
    sig=$(osslsigncode verify -in "$WORK/dl/mt5setup.exe" 2>&1 || true)
    case "$sig" in
      *"Subject: /C=CY/L=Limassol/O=MetaQuotes Ltd/CN=MetaQuotes Ltd"*"Signature verification: ok"*) ;;
      *) echo "the installer's signature did not verify as MetaQuotes Ltd" >&2; exit 3 ;;
    esac
  else
    echo "warning: osslsigncode not installed; the installer's signature was not checked" >&2
  fi
  # /auto installs without questions; it exits non-zero after starting the terminal
  timeout 900 wine "$WORK/dl/mt5setup.exe" /auto >/dev/null 2>&1 || true
  wineserver -k 2>/dev/null || true
  [ -f "$T/MetaEditor64.exe" ] || { echo "MetaTrader 5 was not installed" >&2; exit 3; }
fi

# Compile from a separate folder (C:\vcpwork\MQL5) with it as the include root.
SRC="$WINEPREFIX/drive_c/vcpwork/MQL5"
rm -rf "$WINEPREFIX/drive_c/vcpwork"
for d in Include Scripts Experts; do
  mkdir -p "$SRC/$d"
  cp -r "$ROOT/mql5/$d/VeritasChain" "$SRC/$d/"
done

status=0
for f in 'Scripts\VeritasChain\VCP_SelfTest.mq5' 'Experts\VeritasChain\VCP_ExampleEA.mq5'; do
  unix="$SRC/${f//\\//}"
  log="${unix%.mq5}.log"
  timeout 300 wine "$T/MetaEditor64.exe" "/compile:C:\\vcpwork\\MQL5\\$f" '/inc:C:\vcpwork\MQL5' /log \
    >/dev/null 2>&1 || true   # MetaEditor's exit code is not the compile result
  result=""
  [ -f "$log" ] && result=$(utf8 "$log" | grep '^Result:' || true)
  echo "$f: ${result:-no compiler result}"
  [ -f "$log" ] && { utf8 "$log" | grep -E ' : (error|warning) ' || true; }
  case "$result" in "Result: 0 errors, 0 warnings"*) ;; *) status=1 ;; esac
done
[ "$status" -eq 0 ] || exit 1

# Run the self-test as the startup script of the terminal (portable mode, so its
# data folder is the installation folder), then close the terminal.
mkdir -p "$T/MQL5/Scripts/VeritasChain"
cp "$SRC/Scripts/VeritasChain/VCP_SelfTest.ex5" "$T/MQL5/Scripts/VeritasChain/"
printf '[StartUp]\r\nScript=VeritasChain\\VCP_SelfTest\r\nSymbol=EURUSD\r\nPeriod=H1\r\nShutdownTerminal=1\r\n' \
  > "$WINEPREFIX/drive_c/vcp_selftest.ini"
rm -f "$T"/MQL5/[Ll]ogs/*.log
timeout 600 wine "$T/terminal64.exe" /portable '/config:C:\vcp_selftest.ini' >/dev/null 2>&1 || true
line=""
for l in "$T"/MQL5/[Ll]ogs/*.log; do
  [ -f "$l" ] && line=$(utf8 "$l" | grep -a 'self-test:' | tail -1 || true)
done
for l in "$T"/MQL5/[Ll]ogs/*.log; do [ -f "$l" ] && utf8 "$l" | grep -a 'FAIL' || true; done
echo "${line:-the self-test did not report a result}"
case "$line" in *" 0 failed"*) exit 0 ;; *) exit 1 ;; esac
