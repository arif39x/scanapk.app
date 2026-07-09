Java.perform(function () {
    try {
        var AccessibilityService = Java.use("android.accessibilityservice.AccessibilityService");
        AccessibilityService.onAccessibilityEvent.implementation = function (event) {
            var pkg = event.getPackageName();
            var type = event.getEventType();
            var text = event.getText();
            if (text && text.size() > 0) {
                log("AccessibilityService.onAccessibilityEvent -> pkg=" + pkg + " type=" + type + " text=" + text.get(0));
            } else {
                log("AccessibilityService.onAccessibilityEvent -> pkg=" + pkg + " type=" + type);
            }
            return this.onAccessibilityEvent(event);
        };
    } catch (e) {}
});
