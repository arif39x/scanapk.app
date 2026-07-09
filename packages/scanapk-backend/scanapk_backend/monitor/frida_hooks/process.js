Java.perform(function () {
    try {
        var Runtime = Java.use("java.lang.Runtime");
        Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
            log("Runtime.exec -> " + cmd);
            return this.exec(cmd);
        };
    } catch (e) {}

    try {
        var ProcessBuilder = Java.use("java.lang.ProcessBuilder");
        ProcessBuilder.start.implementation = function () {
            log("ProcessBuilder.start -> " + this.command());
            return this.start();
        };
    } catch (e) {}
});
