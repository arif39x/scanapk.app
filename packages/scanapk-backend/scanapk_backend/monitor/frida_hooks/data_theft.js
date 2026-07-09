Java.perform(function () {
    try {
        var Cursor = Java.use("android.database.Cursor");
        Cursor.getString.implementation = function (col) {
            var val = this.getString(col);
            var snippet = val ? val.substring(0, Math.min(val.length, 100)) : "null";
            log("Cursor.getString col=" + col + " val=" + snippet);
            return val;
        };
    } catch (e) {}

    try {
        var ContentResolver = Java.use("android.content.ContentResolver");
        ContentResolver.query.overload(
            "android.net.Uri", "[Ljava.lang.String;",
            "java.lang.String", "[Ljava.lang.String;",
            "java.lang.String"
        ).implementation = function (uri, proj, sel, args, sort) {
            log("ContentResolver.query -> " + uri.toString());
            return this.query(uri, proj, sel, args, sort);
        };
    } catch (e) {}

    try {
        var AccountManager = Java.use("android.accounts.AccountManager");
        AccountManager.getAccounts.implementation = function () {
            var accounts = this.getAccounts();
            log("AccountManager.getAccounts -> count=" + accounts.length);
            return accounts;
        };
        AccountManager.getPassword.implementation = function (account) {
            var pw = this.getPassword(account);
            log("AccountManager.getPassword -> " + account.name + " type=" + account.type);
            return pw;
        };
    } catch (e) {}

    try {
        var ClipboardManager = Java.use("android.content.ClipboardManager");
        ClipboardManager.getPrimaryClip.implementation = function () {
            var clip = this.getPrimaryClip();
            log("ClipboardManager.getPrimaryClip");
            return clip;
        };
        ClipboardManager.setPrimaryClip.implementation = function (clip) {
            log("ClipboardManager.setPrimaryClip -> " + clip);
            return this.setPrimaryClip(clip);
        };
    } catch (e) {}

    try {
        var PackageManager = Java.use("android.content.pm.PackageManager");
        PackageManager.getInstalledApplications.overload("int").implementation = function (flags) {
            var apps = this.getInstalledApplications(flags);
            log("PackageManager.getInstalledApplications -> count=" + apps.size());
            return apps;
        };
    } catch (e) {}
});
