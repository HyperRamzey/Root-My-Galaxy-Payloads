@echo off
set NDK=C:\Users\admin\AppData\Local\Android\Sdk\ndk\30.0.15729638
set CC=%NDK%\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android35-clang.cmd
set OUTDIR=build\f946b-F946BXXS7GZE5
set TH=-DTARGET_HEADER=\"targets/f946b-F946BXXS7GZE5/target.h\"
if not exist %OUTDIR% mkdir %OUTDIR%

echo === Building preload (root-umh) ===
call %CC% -fPIC -O2 -g0 -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare -Isrc %TH% src/main.c src/util.c src/slide.c src/fops.c src/pipe.c src/root.c src/preload.c -shared -pthread -o %OUTDIR%/cve-2026-43499
if errorlevel 1 (echo PRELOAD BUILD FAILED & exit /b 1)

echo === Building app preload ===
call %CC% -DAPP_PAYLOAD=1 -fPIC -O2 -g0 -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare -Isrc %TH% src/main.c src/util.c src/slide_app.c src/fops.c src/pipe.c src/root.c src/preload.c -shared -pthread -o %OUTDIR%/cve-2026-43499-app.so
if errorlevel 1 (echo APP BUILD FAILED & exit /b 1)

echo === Building root helper ===
call %CC% -fPIE -pie -O2 -g0 -Wall -Wextra src/su_daemon.c -ldl -o %OUTDIR%/cve-2026-43499-root
if errorlevel 1 (echo ROOT HELPER BUILD FAILED & exit /b 1)

echo === ALL BUILDS OK ===
