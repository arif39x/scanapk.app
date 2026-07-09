package com.scanapk.app.model

object ScanHistory {
    private const val MAX_SCANS = 50

    private val _scans = mutableListOf<ScanResult>()
    val scans: List<ScanResult> get() = _scans

    fun addScan(scan: ScanResult) {
        _scans.add(0, scan)
        if (_scans.size > MAX_SCANS) {
            _scans.removeAt(_scans.lastIndex)
        }
    }

    init {
        _scans.addAll(
            listOf(
                ScanResult(
                    id = "1",
                    apkName = "com.example.app-v2.3.apk",
                    packageName = "com.example.app",
                    versionName = "2.3",
                    versionCode = 23,
                    overallScore = 72,
                    severity = "LOW",
                    verdict = "REVIEW",
                    severityCounts = mapOf(
                        Severity.SAFE to 12,
                        Severity.LOW to 3,
                        Severity.MEDIUM to 2,
                        Severity.HIGH to 1,
                        Severity.CRITICAL to 0,
                    ),
                    vulnerabilities = emptyList(),
                    scanTimestamp = System.currentTimeMillis(),
                ),
                ScanResult(
                    id = "2",
                    apkName = "com.sample.game-v1.0.apk",
                    packageName = "com.sample.game",
                    versionName = "1.0",
                    versionCode = 1,
                    overallScore = 45,
                    severity = "MEDIUM",
                    verdict = "DO_NOT_INSTALL",
                    malwareFamily = "Riskware",
                    severityCounts = mapOf(
                        Severity.SAFE to 8,
                        Severity.LOW to 5,
                        Severity.MEDIUM to 4,
                        Severity.HIGH to 2,
                        Severity.CRITICAL to 1,
                    ),
                    vulnerabilities = emptyList(),
                    scanTimestamp = System.currentTimeMillis(),
                ),
            )
        )
    }
}
