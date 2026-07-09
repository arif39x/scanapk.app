Java.perform(function () {
    try {
        var DevicePolicyManager = Java.use("android.app.admin.DevicePolicyManager");
        DevicePolicyManager.lockNow.implementation = function () {
            log("DevicePolicyManager.lockNow");
            return this.lockNow();
        };
        DevicePolicyManager.wipeData.overload("int").implementation = function (flags) {
            log("DevicePolicyManager.wipeData flags=" + flags);
            return this.wipeData(flags);
        };
    } catch (e) {}
});
