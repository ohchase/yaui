# Yaui
Yet Another Unix Injector! 

- Support for arm, aarch64, i386/x86, x86_64.
- Supports for Android bionic linker!

```shell
Yet Another Unix Injector with support for Android/Android Emulator i686/x64/arm/aarch64

Usage: yaui [OPTIONS] --payload <PAYLOAD>

Options:
  -t, --target-pid <TARGET_PID>    Primary process pid targeting functionality
      --target-name <TARGET_NAME>  Secondary process name targeting functionality
  -p, --payload <PAYLOAD>          Relative path to payload dll
  -v, --verbose...                 Increase logging verbosity
  -q, --quiet...                   Decrease logging verbosity
  -h, --help                       Print help
```

## How
By using [ptrace-do](https://github.com/ohchase/ptrace-do) we can invoke remote functions in unix processes. We apply the same window load library injection technique of using the operating system's normal dynamic object load system. Refer to libc's dlopen.

## Building

### linux
```shell
git clone https://github.com/ohchase/yaui
cd yaui
cargo build
./target/debug/yaui --pid 777 --payload evil.so
```

### android
```shell
git clone https://github.com/ohchase/yaui
cd yaui
cross build --target aarch64-linux-android
adb push target/aarch64-linux-android/debug/yaui /data/local/tmp
adb shell "su -c 'chmod +x yaui'"
```

## Usage sample

### By Process Name
```shell
yaui --target_name host-process -p ./target/debug/libpayload.so
```

### By Process Identifier
```shell
yaui -t 777 -p ./target/debug/libpayload.so
```

## Output sample
aarch64-linux-android injection
```shell
gta7litewifi:/data/local/tmp # ./yaui -vv --pid 3615 --payload libpayload.so
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

