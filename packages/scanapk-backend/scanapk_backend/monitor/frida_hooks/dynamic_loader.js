Java.perform(function () {
    // ── DEX Class Loaders ──────────────────────────────────────────────

    try {
        var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
        DexClassLoader.$init.overload(
            "java.lang.String", "java.lang.String",
            "java.lang.String", "java.lang.ClassLoader"
        ).implementation = function (dexPath, optDir, libDir, parent) {
            log("DEXLOAD DexClassLoader.<init> -> path=" + dexPath + " optDir=" + optDir);
            return this.$init(dexPath, optDir, libDir, parent);
        };
    } catch (e) {}

    try {
        var PathClassLoader = Java.use("dalvik.system.PathClassLoader");
        PathClassLoader.$init.overload(
            "java.lang.String", "java.lang.ClassLoader"
        ).implementation = function (path, parent) {
            log("DEXLOAD PathClassLoader.<init> -> " + path);
            return this.$init(path, parent);
        };
        PathClassLoader.$init.overload(
            "java.lang.String", "java.lang.String", "java.lang.ClassLoader"
        ).implementation = function (path, optDir, parent) {
            log("DEXLOAD PathClassLoader.<init>(path, optDir) -> " + path);
            return this.$init(path, optDir, parent);
        };
    } catch (e) {}

    // InMemoryDexClassLoader (Android 8+) — in-memory DEX loading (common in droppers)
    try {
        var IMDCL = Java.use("dalvik.system.InMemoryDexClassLoader");
        IMDCL.$init.overload(
            "java.nio.ByteBuffer", "java.lang.ClassLoader"
        ).implementation = function (buf, parent) {
            log("DEXLOAD InMemoryDexClassLoader.<init>(ByteBuffer) -> remaining=" + buf.remaining() + " bytes, parent=" + (parent ? parent.toString() : "null"));
            return this.$init(buf, parent);
        };
        IMDCL.$init.overload(
            "[Ljava.nio.ByteBuffer;", "java.lang.ClassLoader"
        ).implementation = function (bufs, parent) {
            var total = 0;
            for (var i = 0; i < bufs.length; i++) total += bufs[i].remaining();
            log("DEXLOAD InMemoryDexClassLoader.<init>(ByteBuffer[]) -> total=" + total + " bytes across " + bufs.length + " buffers");
            return this.$init(bufs, parent);
        };
    } catch (e) {}

    // DexFile
    try {
        var DexFile = Java.use("dalvik.system.DexFile");
        DexFile.$init.overload("java.lang.String").implementation = function (path) {
            log("DEXLOAD DexFile.<init> -> " + path);
            return this.$init(path);
        };
        DexFile.loadDex.overload("java.lang.String", "java.lang.String", "int").implementation = function (path, optPath, flags) {
            log("DEXLOAD DexFile.loadDex -> " + path + " flags=" + flags);
            return this.loadDex(path, optPath, flags);
        };
        DexFile.loadClass.implementation = function (name) {
            log("DEXLOAD DexFile.loadClass -> " + name + " from " + this.getName());
            return this.loadClass(name);
        };
    } catch (e) {}

    // ── Reflection-based class loading ─────────────────────────────────

    try {
        var Class = Java.use("java.lang.Class");
        Class.forName.overload("java.lang.String").implementation = function (name) {
            log("DEXLOAD Class.forName -> " + name);
            return this.forName(name);
        };
        Class.forName.overload("java.lang.String", "boolean", "java.lang.ClassLoader").implementation = function (name, init, loader) {
            log("DEXLOAD Class.forName(loader) -> " + name + " loader=" + (loader ? loader.toString() : "null"));
            return this.forName(name, init, loader);
        };
    } catch (e) {}

    try {
        var ClassLoader = Java.use("java.lang.ClassLoader");
        ClassLoader.loadClass.overload("java.lang.String").implementation = function (name) {
            log("DEXLOAD ClassLoader.loadClass -> " + name + " loader=" + this.toString());
            return this.loadClass(name);
        };
        ClassLoader.loadClass.overload("java.lang.String", "boolean").implementation = function (name, resolve) {
            log("DEXLOAD ClassLoader.loadClass(resolve) -> " + name + " loader=" + this.toString());
            return this.loadClass(name, resolve);
        };
    } catch (e) {}

    // ── Reflective method/constructor invocation ─────────────────────

    try {
        var Method = Java.use("java.lang.reflect.Method");
        Method.invoke.overload("java.lang.Object", "[Ljava.lang.Object;").implementation = function (obj, args) {
            var clsName = this.getDeclaringClass().toString();
            var methodName = this.getName();
            log("DEXLOAD Method.invoke -> " + clsName + "." + methodName + "() via reflection");
            return this.invoke(obj, args);
        };
    } catch (e) {}

    try {
        var Constructor = Java.use("java.lang.reflect.Constructor");
        Constructor.newInstance.overload("[Ljava.lang.Object;").implementation = function (args) {
            var clsName = this.getDeclaringClass().toString();
            log("DEXLOAD Constructor.newInstance -> " + clsName + " via reflection");
            return this.newInstance(args);
        };
    } catch (e) {}
});
