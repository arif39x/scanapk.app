Java.perform(function () {
    try {
        var LocationManager = Java.use("android.location.LocationManager");
        LocationManager.getLastKnownLocation.implementation = function (provider) {
            log("LocationManager.getLastKnownLocation -> " + provider);
            return this.getLastKnownLocation(provider);
        };
        LocationManager.requestLocationUpdates.overload(
            "java.lang.String", "long", "float",
            "android.location.LocationListener"
        ).implementation = function (provider, minTime, minDist, listener) {
            log("LocationManager.requestLocationUpdates -> " + provider + " minTime=" + minTime);
            return this.requestLocationUpdates(provider, minTime, minDist, listener);
        };
    } catch (e) {}
});
