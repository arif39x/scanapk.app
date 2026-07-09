Java.perform(function () {
    try {
        var WebView = Java.use("android.webkit.WebView");
        WebView.loadUrl.overload("java.lang.String").implementation = function (url) {
            log("WebView.loadUrl -> " + url);
            return this.loadUrl(url);
        };
        WebView.addJavascriptInterface.overload(
            "java.lang.Object", "java.lang.String"
        ).implementation = function (obj, name) {
            log("WebView.addJavascriptInterface -> name=" + name + " obj=" + obj);
            return this.addJavascriptInterface(obj, name);
        };
        WebView.setWebContentsDebuggingEnabled.implementation = function (enabled) {
            log("WebView.setWebContentsDebuggingEnabled -> " + enabled);
            return this.setWebContentsDebuggingEnabled(enabled);
        };
        WebView.evaluateJavascript.overload("java.lang.String", "android.webkit.ValueCallback").implementation = function (script, cb) {
            log("WebView.evaluateJavascript -> " + script);
            return this.evaluateJavascript(script, cb);
        };
    } catch (e) {}

    try {
        var WebSettings = Java.use("android.webkit.WebSettings");
        WebSettings.setJavaScriptEnabled.implementation = function (enabled) {
            log("WebSettings.setJavaScriptEnabled -> " + enabled);
            return this.setJavaScriptEnabled(enabled);
        };
        WebSettings.setAllowFileAccess.implementation = function (allow) {
            log("WebSettings.setAllowFileAccess -> " + allow);
            return this.setAllowFileAccess(allow);
        };
        WebSettings.setAllowContentAccess.implementation = function (allow) {
            log("WebSettings.setAllowContentAccess -> " + allow);
            return this.setAllowContentAccess(allow);
        };
    } catch (e) {}
});
