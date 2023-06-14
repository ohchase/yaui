# YAUI
Yet Another ~~freaking~~ Unix Injector! 

- Support for arm, aarch64, i386/x86, x86_64.
- Supports for Android bionic linker! 
- *Kinda* Supports Android Emulators

## How
By using [ptrace-do](https://github.com/ohchase/ptrace-do) we can invoke remote functions in unix processes. We apply the same window load library injection technique of using the operating system's normal dynamic object load system. Refer to libc's dlopen

## Build

```shell
git clone https://github.com/ohchase/yaui
cd yaui
cargo build
./target/debug/yaui --pid 777 --payload evil.so
```

android ish
```
git clone https://github.com/ohchase/yaui
cd yaui
cross build --target aarch64-linux-android
adb push target/aarch64-linux-android/debug/yaui /data/local/tmp
adb shell "su -c 'chmod +x yaui'"
```

## Gotchas

Injecting on android has gotchas due to SE-Linux.
If you just inject a typical shared object from /data/local/tmp into an app, it won't map an executable section of the payload. The payload will be visible in the app's proc maps but won't have had its ctor called. 

Fadeevab found a solution for this; allllll the way at the bottom :)

https://fadeevab.com/shared-library-injection-on-android-8/

```shell
SELinux Label for Injection Library

The final step is to overcome SELinux that denies to mmap a shared library from /data. Use the same trick with a label as before:

chcon -v u:object_r:apk_data_file:s0 /data/local/tmp/libinject.so
```


## Usage sample

By Process Name
```shell
yaui --target host-process --payload /target/debug/libpayload.so
```

By Process Identifier
```shell
yaui --pid 777 --payload /target/debug/libpayload.so
```

## Output sample
aarch64-linux-android injection

```shell
gta7litewifi:/data/local/tmp # ./yaui --pid 3615 --payload libpayload.so
21:58:46.796938Z  INFO yaui: Yaui: Yet another unix injector!
21:58:46.813933Z  INFO yaui: Target payload: libpayload.so
21:58:46.814144Z  INFO yaui: Target pid for injection: 3615
21:58:47.076213Z  WARN yaui: Using injection configs: InjectConfig {
    spoof_so_path: "/apex/com.android.runtime/lib64/bionic/libc.so",
    allocater_so_path: "/apex/com.android.runtime/lib64/bionic/libc.so",
    linker_so_path: "/apex/com.android.runtime/lib64/bionic/libdl.so",
}
21:58:47.076937Z  INFO yaui: Injecting Payload: "/data/local/tmp/libpayload.so" into Pid: 3615
21:58:47.077242Z  INFO yaui: Successfully attached to the process
21:58:47.080813Z  INFO yaui: Identifed internal range "/apex/com.android.runtime/lib64/bionic/libc.so" at 7C19F4E000
21:58:47.206350Z  INFO yaui: Identifed remote range "/apex/com.android.runtime/lib64/bionic/libc.so" at 7637688000
21:58:47.206574Z  INFO yaui: Identified remote mmap procedure at 7637760400
21:58:47.210182Z  INFO yaui: Identifed internal range "/apex/com.android.runtime/lib64/bionic/libdl.so" at 7C19F09000
21:58:47.336861Z  INFO yaui: Identifed remote range "/apex/com.android.runtime/lib64/bionic/libdl.so" at 763BA16000
21:58:47.337073Z  INFO yaui: Identified remote dlerror procedure at 763ba17030
21:58:47.340718Z  INFO yaui: Identifed internal range "/apex/com.android.runtime/lib64/bionic/libdl.so" at 7C19F09000
21:58:47.468265Z  INFO yaui: Identifed remote range "/apex/com.android.runtime/lib64/bionic/libdl.so" at 763BA16000
21:58:47.468540Z  INFO yaui: Identified remote dlopen procedure at 763ba17018
21:58:47.594403Z  INFO yaui: Identified spoof module base address for return address: 7637688000
21:58:47.594596Z  INFO ptrace_do: WaitStatus { is_stopped: true, is_signaled: false, is_continued: false, is_exited: false, stop_code: 19 }
21:58:47.594681Z  INFO yaui: Successfully waited for the mmap frame
21:58:47.595591Z  INFO ptrace_do: WaitStatus { is_stopped: true, is_signaled: false, is_continued: false, is_exited: false, stop_code: 11 }
21:58:47.595810Z  INFO yaui: Mmap was successful created new mapping at 763cb5d000 with size 1000
21:58:47.596081Z  INFO yaui: Successfully wrote payload location to 763cb5d000
21:58:47.600293Z  INFO ptrace_do: WaitStatus { is_stopped: true, is_signaled: false, is_continued: false, is_exited: false, stop_code: 11 }
21:58:47.600665Z  INFO yaui: Executed remote dlopen function
21:58:47.600783Z  INFO yaui: Successfully executed remote dlopen function
21:58:47.600888Z  INFO ptrace_do: Successfully detached from Pid: 3615
```

## Showcase

- Yaui to inject shared object payload
- Plt-rs to crawl link maps on android/linux to hook eglSwapBuffers
- EGui and Glow renderer

![Alt text](media/android-poc.jpg "Android POC")

