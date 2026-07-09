var TAG = "[MALMON]";

function log(msg) {
    console.log(TAG + " " + msg);
    try {
        Java.use("android.util.Log").i(TAG, msg);
    } catch (e) {}
}

function bytesToHex(bytes) {
    if (!bytes) return "null";
    var hex = [];
    for (var i = 0; i < Math.min(bytes.length, 32); i++) {
        hex.push(("0" + (bytes[i] & 0xFF).toString(16)).slice(-2));
    }
    return hex.join("");
}

log("Frida runtime ready — loading hooks");
