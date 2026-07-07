package com.scanapk.app.model

data class ScanResult(
    val id: String,
    val apkName: String,
    val packageName: String,
    val versionName: String,
    val versionCode: Int,
    val overallScore: Int,
    val severityCounts: Map<Severity, Int>,
    val vulnerabilities: List<Vulnerability>,
    val scanTimestamp: Long,
)

data class Vulnerability(
    val id: String,
    val title: String,
    val description: String,
    val severity: Severity,
    val category: String,
)
