Java.perform(function () {
    var startTime = Date.now();

    function elapsed() {
        return (Date.now() - startTime) / 1000;
    }

    // Handler.postDelayed — common UI-thread timer
    try {
        var Handler = Java.use("android.os.Handler");
        Handler.postDelayed.overload("java.lang.Runnable", "long").implementation = function (r, delay) {
            log("TIMER Handler.postDelayed -> delay=" + delay + "ms at t=" + elapsed().toFixed(1) + "s");
            return this.postDelayed(r, delay);
        };
        Handler.postDelayed.overload("java.lang.Runnable", "java.lang.Object", "long").implementation = function (r, token, delay) {
            log("TIMER Handler.postDelayed(token) -> delay=" + delay + "ms at t=" + elapsed().toFixed(1) + "s");
            return this.postDelayed(r, token, delay);
        };
    } catch (e) {}

    // Thread.sleep — naive delay
    try {
        var Thread = Java.use("java.lang.Thread");
        Thread.sleep.overload("long").implementation = function (ms) {
            log("TIMER Thread.sleep -> " + ms + "ms at t=" + elapsed().toFixed(1) + "s");
            return this.sleep(ms);
        };
        Thread.sleep.overload("long", "int").implementation = function (ms, nanos) {
            log("TIMER Thread.sleep(nanos) -> " + ms + "ms + " + nanos + "ns at t=" + elapsed().toFixed(1) + "s");
            return this.sleep(ms, nanos);
        };
    } catch (e) {}

    // SystemClock.sleep — Android-specific sleep
    try {
        var SystemClock = Java.use("android.os.SystemClock");
        SystemClock.sleep.implementation = function (ms) {
            log("TIMER SystemClock.sleep -> " + ms + "ms at t=" + elapsed().toFixed(1) + "s");
            return this.sleep(ms);
        };
    } catch (e) {}

    // System.currentTimeMillis — time-based comparison checks
    try {
        var System = Java.use("java.lang.System");
        System.currentTimeMillis.implementation = function () {
            var ret = this.currentTimeMillis();
            // Only log time queries that look like comparison checks
            var trace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
            if (trace.indexOf("currentTimeMillis") === -1) return ret;
            return ret;
        };
    } catch (e) {}

    // SystemClock.elapsedRealtime / uptimeMillis — time queries
    try {
        var SystemClock = Java.use("android.os.SystemClock");
        SystemClock.elapsedRealtime.implementation = function () {
            var ret = this.elapsedRealtime();
            log("TIMER SystemClock.elapsedRealtime() -> " + ret + "ms at t=" + elapsed().toFixed(1) + "s");
            return ret;
        };
    } catch (e) {}

    try {
        var SystemClock = Java.use("android.os.SystemClock");
        SystemClock.uptimeMillis.implementation = function () {
            var ret = this.uptimeMillis();
            log("TIMER SystemClock.uptimeMillis() -> " + ret + "ms at t=" + elapsed().toFixed(1) + "s");
            return ret;
        };
    } catch (e) {}

    // java.util.Timer
    try {
        var Timer = Java.use("java.util.Timer");
        Timer.schedule.overload("java.util.TimerTask", "long").implementation = function (task, delay) {
            log("TIMER Timer.schedule -> delay=" + delay + "ms at t=" + elapsed().toFixed(1) + "s");
            return this.schedule(task, delay);
        };
        Timer.schedule.overload("java.util.TimerTask", "java.util.Date").implementation = function (task, time) {
            log("TIMER Timer.schedule(date) -> time=" + time.toString() + " at t=" + elapsed().toFixed(1) + "s");
            return this.schedule(task, time);
        };
        Timer.scheduleAtFixedRate.overload("java.util.TimerTask", "long", "long").implementation = function (task, delay, period) {
            log("TIMER Timer.scheduleAtFixedRate -> delay=" + delay + "ms period=" + period + "ms at t=" + elapsed().toFixed(1) + "s");
            return this.scheduleAtFixedRate(task, delay, period);
        };
    } catch (e) {}

    // AlarmManager
    try {
        var AlarmManager = Java.use("android.app.AlarmManager");
        AlarmManager.set.overload("int", "long", "android.app.PendingIntent").implementation = function (type, triggerAt, intent) {
            log("TIMER AlarmManager.set -> type=" + type + " triggerAt=" + triggerAt + "ms at t=" + elapsed().toFixed(1) + "s");
            return this.set(type, triggerAt, intent);
        };
        AlarmManager.setWindow.overload("int", "long", "long", "android.app.PendingIntent").implementation = function (type, triggerAt, window, intent) {
            log("TIMER AlarmManager.setWindow -> type=" + type + " triggerAt=" + triggerAt + "ms at t=" + elapsed().toFixed(1) + "s");
            return this.setWindow(type, triggerAt, window, intent);
        };
        AlarmManager.setExact.overload("int", "long", "android.app.PendingIntent").implementation = function (type, triggerAt, intent) {
            log("TIMER AlarmManager.setExact -> type=" + type + " triggerAt=" + triggerAt + "ms at t=" + elapsed().toFixed(1) + "s");
            return this.setExact(type, triggerAt, intent);
        };
    } catch (e) {}

    // ScheduledThreadPoolExecutor
    try {
        var STPE = Java.use("java.util.concurrent.ScheduledThreadPoolExecutor");
        STPE.schedule.overload("java.lang.Runnable", "long", "java.util.concurrent.TimeUnit").implementation = function (cmd, delay, unit) {
            log("TIMER ScheduledThreadPoolExecutor.schedule -> delay=" + delay + " " + unit.toString() + " at t=" + elapsed().toFixed(1) + "s");
            return this.schedule(cmd, delay, unit);
        };
        STPE.scheduleWithFixedDelay.overload("java.lang.Runnable", "long", "long", "java.util.concurrent.TimeUnit").implementation = function (cmd, initDelay, delay, unit) {
            log("TIMER ScheduledThreadPoolExecutor.scheduleWithFixedDelay -> initDelay=" + initDelay + " delay=" + delay + " " + unit.toString() + " at t=" + elapsed().toFixed(1) + "s");
            return this.scheduleWithFixedDelay(cmd, initDelay, delay, unit);
        };
        STPE.scheduleAtFixedRate.overload("java.lang.Runnable", "long", "long", "java.util.concurrent.TimeUnit").implementation = function (cmd, initDelay, period, unit) {
            log("TIMER ScheduledThreadPoolExecutor.scheduleAtFixedRate -> initDelay=" + initDelay + " period=" + period + " " + unit.toString() + " at t=" + elapsed().toFixed(1) + "s");
            return this.scheduleAtFixedRate(cmd, initDelay, period, unit);
        };
    } catch (e) {}

    // CountDownTimer
    try {
        var CountDownTimer = Java.use("android.os.CountDownTimer");
        CountDownTimer.$init.overload("long", "long").implementation = function (total, interval) {
            log("TIMER CountDownTimer -> total=" + total + "ms interval=" + interval + "ms at t=" + elapsed().toFixed(1) + "s");
            return this.$init(total, interval);
        };
    } catch (e) {}

    // View.OnClickListener — detect when UI interaction is expected
    try {
        var View = Java.use("android.view.View");
        View.setOnClickListener.implementation = function (listener) {
            log("UI OnClickListener registered for at t=" + elapsed().toFixed(1) + "s");
            return this.setOnClickListener(listener);
        };
    } catch (e) {}

    try {
        var View = Java.use("android.view.View");
        View.setOnLongClickListener.implementation = function (listener) {
            log("UI OnLongClickListener registered at t=" + elapsed().toFixed(1) + "s");
            return this.setOnLongClickListener(listener);
        };
    } catch (e) {}

    // Dialog show — malware often waits for dialog interaction
    try {
        var Dialog = Java.use("android.app.Dialog");
        Dialog.show.implementation = function () {
            log("UI Dialog.show at t=" + elapsed().toFixed(1) + "s");
            return this.show();
        };
    } catch (e) {}

    try {
        var AlertDialog = Java.use("android.app.AlertDialog");
        AlertDialog.show.implementation = function () {
            log("UI AlertDialog.show at t=" + elapsed().toFixed(1) + "s");
            return this.show();
        };
    } catch (e) {}
});
