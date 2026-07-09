Java.perform(function () {
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.doFinal.overload("[B").implementation = function (input) {
            log("Cipher.doFinal bytes=" + input.length);
            return this.doFinal(input);
        };
    } catch (e) {}

    try {
        var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
        SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function (key, algo) {
            log("SecretKeySpec algo=" + algo + " key=" + bytesToHex(key));
            return this.$init(key, algo);
        };
    } catch (e) {}
});
