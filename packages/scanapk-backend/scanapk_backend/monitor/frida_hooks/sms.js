Java.perform(function () {
    try {
        var SmsManager = Java.use("android.telephony.SmsManager");
        SmsManager.sendTextMessage.overload(
            "java.lang.String", "java.lang.String",
            "java.lang.String", "android.app.PendingIntent",
            "android.app.PendingIntent"
        ).implementation = function (dest, sc, text, sent, deliv) {
            log("SMS.sendTextMessage -> to=" + dest + " body=" + text);
            return this.sendTextMessage(dest, sc, text, sent, deliv);
        };
    } catch (e) {}

    try {
        var TelephonyManager = Java.use("android.telephony.TelephonyManager");
        TelephonyManager.getDeviceId.implementation = function () {
            var id = this.getDeviceId();
            log("TelephonyManager.getDeviceId -> " + id);
            return id;
        };
        TelephonyManager.getImei.implementation = function () {
            var imei = this.getImei();
            log("TelephonyManager.getImei -> " + imei);
            return imei;
        };
        TelephonyManager.getSubscriberId.implementation = function () {
            var id = this.getSubscriberId();
            log("TelephonyManager.getSubscriberId -> " + id);
            return id;
        };
    } catch (e) {}
});
