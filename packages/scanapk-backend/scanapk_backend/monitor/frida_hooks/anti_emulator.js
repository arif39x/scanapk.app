Java.perform(function () {
    try {
        var Build = Java.use("android.os.Build");
        Build.FINGERPRINT.value = "samsung/beyond1/beyond1:11/RP1A.200720.012/G991BXXU3CUID:user/release-keys";
        Build.MODEL.value = "SM-G991B";
        Build.MANUFACTURER.value = "samsung";
        Build.TAGS.value = "release-keys";
        Build.TYPE.value = "user";
        Build.HARDWARE.value = "qcom";
        log("anti_emulator: spoofed android.os.Build fields");
    } catch (e) {
        log("anti_emulator: Build field hook error: " + e);
    }

    try {
        var SystemProperties = Java.use("android.os.SystemProperties");
        SystemProperties.get.overload("java.lang.String").implementation = function (key) {
            if (key === "ro.build.tags") return "release-keys";
            if (key === "ro.debuggable") return "0";
            if (key === "ro.secure") return "1";
            if (key === "ro.build.type") return "user";
            return this.get(key);
        };
        log("anti_emulator: hooked SystemProperties.get(String)");
    } catch (e) {
        log("anti_emulator: SystemProperties.get(String) hook error: " + e);
    }

    try {
        var SystemProperties = Java.use("android.os.SystemProperties");
        SystemProperties.get.overload("java.lang.String", "java.lang.String").implementation = function (key, def) {
            if (key === "ro.build.tags") return "release-keys";
            if (key === "ro.debuggable") return "0";
            if (key === "ro.secure") return "1";
            if (key === "ro.build.type") return "user";
            return this.get(key, def);
        };
        log("anti_emulator: hooked SystemProperties.get(String, String)");
    } catch (e) {
        log("anti_emulator: SystemProperties.get(String, String) hook error: " + e);
    }

    try {
        var File = Java.use("java.io.File");
        File.exists.implementation = function () {
            var path = this.getAbsolutePath();
            var blocked = [
                "/dev/socket/qemud",
                "/dev/qemu_pipe",
                "/system/lib/libc_malloc_debug_qemu.so",
                "/sys/qemu_trace",
                "/system/bin/qemu-props",
            ];
            for (var i = 0; i < blocked.length; i++) {
                if (path.indexOf(blocked[i]) !== -1) {
                    log("anti_emulator: blocked File.exists() check -> " + path);
                    return false;
                }
            }
            return this.exists();
        };
        log("anti_emulator: hooked File.exists()");
    } catch (e) {
        log("anti_emulator: File.exists() hook error: " + e);
    }
});
