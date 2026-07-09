Java.perform(function () {
    try {
        var FileOutputStream = Java.use("java.io.FileOutputStream");
        FileOutputStream.write.overload("[B").implementation = function (b) {
            log("FileOutputStream.write -> " + this.getFD());
            return this.write(b);
        };
    } catch (e) {}

    try {
        var FileInputStream = Java.use("java.io.FileInputStream");
        FileInputStream.read.overload("[B").implementation = function (b) {
            var ret = this.read(b);
            log("FileInputStream.read -> " + this.getFD() + " bytes=" + ret);
            return ret;
        };
    } catch (e) {}
});
