Java.perform(function () {
    try {
        var NotificationListenerService = Java.use("android.service.notification.NotificationListenerService");
        NotificationListenerService.onNotificationPosted.implementation = function (sbn) {
            var pkg = sbn.getPackageName();
            var text = sbn.getNotification().tickerText;
            log("NotificationListener.onNotificationPosted -> pkg=" + pkg + " text=" + text);
            return this.onNotificationPosted(sbn);
        };
    } catch (e) {}
});
