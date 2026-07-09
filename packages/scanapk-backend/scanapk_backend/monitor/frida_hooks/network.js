Java.perform(function () {
    // ── Standard URL Connections ───────────────────────────────────────

    try {
        var URL = Java.use("java.net.URL");
        URL.openConnection.implementation = function () {
            log("NET URL.openConnection -> " + this.toString());
            return this.openConnection();
        };
        URL.openStream.implementation = function () {
            log("NET URL.openStream -> " + this.toString());
            return this.openStream();
        };
    } catch (e) {}

    try {
        var HttpURLConnection = Java.use("java.net.HttpURLConnection");
        HttpURLConnection.getInputStream.implementation = function () {
            log("NET HttpURLConnection.getInputStream -> " + this.getURL());
            return this.getInputStream();
        };
        HttpURLConnection.getOutputStream.implementation = function () {
            log("NET HttpURLConnection.getOutputStream -> " + this.getURL());
            return this.getOutputStream();
        };
        HttpURLConnection.getResponseCode.implementation = function () {
            var code = this.getResponseCode();
            log("NET HttpURLConnection.responseCode -> " + this.getURL() + " code=" + code);
            return code;
        };
        HttpURLConnection.getContentLength.implementation = function () {
            var len = this.getContentLength();
            if (len > 10240) {
                log("NET HttpURLConnection.largePayload -> " + this.getURL() + " size=" + len + " bytes");
            }
            return len;
        };
    } catch (e) {}

    try {
        var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsURLConnection.getInputStream.implementation = function () {
            log("NET HttpsURLConnection.getInputStream -> " + this.getURL());
            return this.getInputStream();
        };
        HttpsURLConnection.getOutputStream.implementation = function () {
            log("NET HttpsURLConnection.getOutputStream -> " + this.getURL());
            return this.getOutputStream();
        };
    } catch (e) {}

    // ── OkHttp ───────────────────────────────────────────────────────

    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        OkHttpClient.newCall.implementation = function (request) {
            log("NET OkHttp.newCall -> " + request.url());
            return this.newCall(request);
        };
    } catch (e) {}

    try {
        var Response = Java.use("okhttp3.Response");
        Response.body.implementation = function () {
            var body = this.body();
            if (body) {
                var len = body.contentLength();
                if (len > 10240) {
                    log("NET OkHttp.largeResponse -> " + this.request().url() + " size=" + len + " bytes");
                }
            }
            return body;
        };
    } catch (e) {}

    // ── Socket connections ─────────────────────────────────────────────

    try {
        var Socket = Java.use("java.net.Socket");
        Socket.connect.implementation = function (addr, timeout) {
            log("NET Socket.connect -> " + addr.toString() + " timeout=" + timeout);
            return this.connect(addr, timeout);
        };
    } catch (e) {}

    // ── DownloadManager ──────────────────────────────────────────────

    try {
        var DownloadManager = Java.use("android.app.DownloadManager");
        DownloadManager.enqueue.implementation = function (request) {
            try {
                var uri = request.getUri();
                log("NET DownloadManager.enqueue -> URI=" + uri.toString());
            } catch (e2) {
                log("NET DownloadManager.enqueue -> (uri unknown)");
            }
            return this.enqueue(request);
        };
    } catch (e) {}

    try {
        var DownloadManagerRequest = Java.use("android.app.DownloadManager$Request");
        DownloadManagerRequest.setDestinationUri.implementation = function (uri) {
            log("NET DownloadManager.setDestinationUri -> " + uri.toString());
            return this.setDestinationUri(uri);
        };
        DownloadManagerRequest.setDestinationInExternalFilesDir.implementation = function (ctx, dirType, subPath) {
            log("NET DownloadManager.setDestinationInExternalFilesDir -> " + dirType + "/" + subPath);
            return this.setDestinationInExternalFilesDir(ctx, dirType, subPath);
        };
    } catch (e) {}

    // ── WebView — common in droppers to fetch payloads ──────────────

    try {
        var WebView = Java.use("android.webkit.WebView");
        WebView.loadUrl.overload("java.lang.String").implementation = function (url) {
            log("NET WebView.loadUrl -> " + url);
            return this.loadUrl(url);
        };
        WebView.loadUrl.overload("java.lang.String", "java.util.Map").implementation = function (url, headers) {
            log("NET WebView.loadUrl(headers) -> " + url);
            return this.loadUrl(url, headers);
        };
        WebView.postUrl.implementation = function (url, data) {
            log("NET WebView.postUrl -> " + url + " dataLen=" + (data ? data.length : 0));
            return this.postUrl(url, data);
        };
        WebView.evaluateJavascript.implementation = function (script, cb) {
            log("NET WebView.evaluateJavascript -> " + (script ? script.substring(0, 80) : "null"));
            return this.evaluateJavascript(script, cb);
        };
    } catch (e) {}
});
