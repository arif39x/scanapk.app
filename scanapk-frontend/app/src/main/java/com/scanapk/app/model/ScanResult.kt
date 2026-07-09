package com.scanapk.app.model

data class ScanResult(
    val id: String,
    val apkName: String,
    val packageName: String,
    val versionName: String,
    val versionCode: Int,
    val overallScore: Int,
    val severity: String = "UNKNOWN",
    val verdict: String = "UNKNOWN",
    val malwareFamily: String? = null,
    val severityCounts: Map<Severity, Int> = emptyMap(),
    val vulnerabilities: List<Vulnerability> = emptyList(),
    val keyFindings: List<String> = emptyList(),
    val recommendations: List<String> = emptyList(),
    val threatTypes: List<String> = emptyList(),
    val scanTimestamp: Long,
    val yaraMatchCount: Int = 0,
    val suspiciousApiCount: Int = 0,
    val trackerCount: Int = 0,
    val urlCount: Int = 0,
    val ipCount: Int = 0,
    val nativeLibCount: Int = 0,
    val dangerousPermissionCount: Int = 0,
    val exfiltrationChainCount: Int = 0,
    val scoreBreakdown: Map<String, Int> = emptyMap(),
)

data class Vulnerability(
    val id: String,
    val title: String,
    val description: String,
    val severity: Severity,
    val category: String,
)
