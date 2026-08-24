@echo off
set NDK=C:\Users\admin\AppData\Local\Android\Sdk\ndk\30.0.15729638
set CC=%NDK%\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android35-clang.cmd
set TH=-DTARGET_HEADER=\"targets/f946b-F946BXXS7GZE5/target.h\"
call %CC% -O1 -g0 -Wall -Wextra -Isrc %TH% tests/workdir_probe_main.c src/main.c src/util.c src/slide.c src/fops.c src/pipe.c src/root.c -pthread -o build\workdir_probe
if errorlevel 1 (echo PROBE BUILD FAILED & exit /b 1)
echo PROBE-BUILD-OK
