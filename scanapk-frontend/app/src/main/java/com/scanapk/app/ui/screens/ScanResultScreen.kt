package com.scanapk.app.ui.screens

import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.scanapk.app.model.ScanResult
import com.scanapk.app.model.Severity
import com.scanapk.app.model.Vulnerability
import com.scanapk.app.ui.components.ScanCard
import com.scanapk.app.ui.components.SeverityChip
import com.scanapk.app.ui.theme.SeverityCritical
import com.scanapk.app.ui.theme.SeverityHigh
import com.scanapk.app.ui.theme.SeverityLow
import com.scanapk.app.ui.theme.SeverityMedium
import com.scanapk.app.ui.theme.SeveritySafe
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.util.UUID

@Composable
fun ScanResultScreen(
    scanResult: ScanResult = sampleResult,
    apkUri: Uri? = null,
) {
    var scannedResult by remember { mutableStateOf<ScanResult?>(null) }
    var isScanning by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }
    val context = LocalContext.current

    LaunchedEffect(apkUri) {
        if (apkUri != null) {
            isScanning = true
            errorMessage = null
            scannedResult = null
            val result = withContext(Dispatchers.IO) {
                scanApk(context, apkUri)
            }
            if (result != null) {
                scannedResult = result
            } else {
                errorMessage = "Failed to scan APK. The file may be invalid or inaccessible."
            }
            isScanning = false
        }
    }

    val displayResult = scannedResult ?: scanResult

    if (isScanning) {
        Box(
            modifier = Modifier.fillMaxSize(),
            contentAlignment = Alignment.Center,
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                CircularProgressIndicator(
                    modifier = Modifier.size(48.dp),
                    color = MaterialTheme.colorScheme.primary,
                )
                Spacer(modifier = Modifier.height(16.dp))
                Text(
                    text = "Scanning APK...",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodyLarge,
                )
            }
        }
    } else if (errorMessage != null) {
        Box(
            modifier = Modifier.fillMaxSize(),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                text = errorMessage ?: "",
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodyLarge,
            )
        }
    } else {
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            item {
                Spacer(modifier = Modifier.height(8.dp))
                ScoreCard(scanResult = displayResult)
            }

            item {
                SeverityBreakdown(severityCounts = displayResult.severityCounts)
            }

            item {
                Text(
                    text = "Vulnerabilities",
                    style = MaterialTheme.typography.headlineSmall,
                )
            }

            items(displayResult.vulnerabilities) { vuln ->
                VulnerabilityCard(vulnerability = vuln)
            }

            if (displayResult.vulnerabilities.isEmpty()) {
                item {
                    ScanCard(modifier = Modifier.fillMaxWidth()) {
                        Text(
                            text = "No vulnerabilities found",
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(vertical = 8.dp),
                        )
                    }
                }
            }

            item {
                Spacer(modifier = Modifier.height(24.dp))
            }
        }
    }
}

@Suppress("DEPRECATION")
private suspend fun scanApk(context: Context, uri: Uri): ScanResult? {
    return try {
        val tempFile = File(context.cacheDir, "scan_${System.currentTimeMillis()}.apk")
        try {
            context.contentResolver.openInputStream(uri)?.use { input ->
                tempFile.outputStream().use { output ->
                    input.copyTo(output)
                }
            } ?: return null

            val pm = context.packageManager
            val pi = pm.getPackageArchiveInfo(
                tempFile.absolutePath,
                PackageManager.GET_ACTIVITIES or PackageManager.GET_PERMISSIONS
            ) ?: return null

            val pkgName = pi.packageName
            val versionName = pi.versionName ?: "1.0"
            val versionCode = pi.versionCode
            val apkName = "${pkgName}-v${versionName}.apk"

            val manifestPerms = pi.requestedPermissions ?: emptyArray()
            val vulnerabilities = mutableListOf<Vulnerability>()

            manifestPerms.forEach { perm ->
                when {
                    perm.contains("READ_CONTACTS") -> vulnerabilities.add(
                        Vulnerability(
                            id = UUID.randomUUID().toString(),
                            title = "Reads Contacts",
                            description = "Application requests permission to read user contacts, which may pose a privacy risk.",
                            severity = Severity.MEDIUM,
                            category = "Privacy",
                        )
                    )
                    perm.contains("CAMERA") -> vulnerabilities.add(
                        Vulnerability(
                            id = UUID.randomUUID().toString(),
                            title = "Camera Access",
                            description = "Application requests camera access, which could be used for unauthorized recording.",
                            severity = Severity.MEDIUM,
                            category = "Privacy",
                        )
                    )
                    perm.contains("RECORD_AUDIO") && !perm.contains("BIND") -> vulnerabilities.add(
                        Vulnerability(
                            id = UUID.randomUUID().toString(),
                            title = "Audio Recording",
                            description = "Application can record audio without user interaction.",
                            severity = Severity.HIGH,
                            category = "Privacy",
                        )
                    )
                    perm.contains("ACCESS_FINE_LOCATION") || perm.contains("ACCESS_COARSE_LOCATION") -> vulnerabilities.add(
                        Vulnerability(
                            id = UUID.randomUUID().toString(),
                            title = "Location Tracking",
                            description = "Application can access device location, potentially tracking user movement.",
                            severity = Severity.HIGH,
                            category = "Privacy",
                        )
                    )
                    perm.contains("SMS") && !perm.contains("BIND") && !perm.contains("SEND") -> vulnerabilities.add(
                        Vulnerability(
                            id = UUID.randomUUID().toString(),
                            title = "SMS Access",
                            description = "Application can read or intercept SMS messages, potentially capturing sensitive information.",
                            severity = Severity.CRITICAL,
                            category = "Privacy",
                        )
                    )
                    perm.contains("READ_PHONE_STATE") -> vulnerabilities.add(
                        Vulnerability(
                            id = UUID.randomUUID().toString(),
                            title = "Phone State Access",
                            description = "Application can access device identifiers like IMEI, which can be used for device tracking.",
                            severity = Severity.MEDIUM,
                            category = "Privacy",
                        )
                    )
                    perm.contains("READ_CALENDAR") -> vulnerabilities.add(
                        Vulnerability(
                            id = UUID.randomUUID().toString(),
                            title = "Calendar Access",
                            description = "Application can read calendar events, potentially accessing personal schedule information.",
                            severity = Severity.MEDIUM,
                            category = "Privacy",
                        )
                    )
                    perm.contains("BODY_SENSORS") -> vulnerabilities.add(
                        Vulnerability(
                            id = UUID.randomUUID().toString(),
                            title = "Body Sensor Access",
                            description = "Application can access sensor data like heart rate, potentially exposing health information.",
                            severity = Severity.MEDIUM,
                            category = "Privacy",
                        )
                    )
                    perm.contains("ACTIVITY_RECOGNITION") -> vulnerabilities.add(
                        Vulnerability(
                            id = UUID.randomUUID().toString(),
                            title = "Activity Recognition",
                            description = "Application can recognize user activity patterns, potentially inferring behavior.",
                            severity = Severity.LOW,
                            category = "Privacy",
                        )
                    )
                }
            }

            val appFlags = pi.applicationInfo?.flags ?: 0
            val isDebuggable = appFlags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE != 0
            if (isDebuggable) {
                vulnerabilities.add(
                    Vulnerability(
                        id = UUID.randomUUID().toString(),
                        title = "Debuggable Application",
                        description = "The APK is built in debug mode, which should not be used for production releases.",
                        severity = Severity.HIGH,
                        category = "Code Quality",
                    )
                )
            }

            val severityCounts = mutableMapOf(
                Severity.SAFE to 0,
                Severity.LOW to 0,
                Severity.MEDIUM to 0,
                Severity.HIGH to 0,
                Severity.CRITICAL to 0,
            )
            vulnerabilities.forEach { vuln ->
                severityCounts[vuln.severity] = (severityCounts[vuln.severity] ?: 0) + 1
            }
            val totalAnalyzed = 10
            severityCounts[Severity.SAFE] = totalAnalyzed - vulnerabilities.size

            val deductions = vulnerabilities.sumOf { vuln ->
                val points: Int = when (vuln.severity) {
                    Severity.LOW -> 5
                    Severity.MEDIUM -> 10
                    Severity.HIGH -> 20
                    Severity.CRITICAL -> 35
                    else -> 0
                }
                points
            }
            val overallScore = maxOf(0, 100 - deductions)

            ScanResult(
                id = UUID.randomUUID().toString(),
                apkName = apkName,
                packageName = pkgName,
                versionName = versionName,
                versionCode = versionCode,
                overallScore = overallScore,
                severityCounts = severityCounts.toMap(),
                vulnerabilities = vulnerabilities,
                scanTimestamp = System.currentTimeMillis(),
            )
        } finally {
            if (tempFile.exists()) {
                tempFile.delete()
            }
        }
    } catch (e: Exception) {
        e.printStackTrace()
        null
    }
}

@Composable
private fun ScoreCard(scanResult: ScanResult) {
    ScanCard(modifier = Modifier.fillMaxWidth()) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(
                text = "${scanResult.overallScore}",
                fontSize = 64.sp,
                fontWeight = FontWeight.Light,
                letterSpacing = (-0.02).sp,
                color = when {
                    scanResult.overallScore >= 80 -> SeveritySafe
                    scanResult.overallScore >= 60 -> SeverityLow
                    scanResult.overallScore >= 40 -> SeverityMedium
                    scanResult.overallScore >= 20 -> SeverityHigh
                    else -> SeverityCritical
                },
            )
            Text(
                text = "Security Score",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.labelLarge,
            )
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = scanResult.apkName,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodyMedium,
            )
        }
    }
}

@Composable
private fun SeverityBreakdown(severityCounts: Map<Severity, Int>) {
    ScanCard(modifier = Modifier.fillMaxWidth()) {
        Text(
            text = "Severity Breakdown",
            fontWeight = FontWeight.Bold,
            fontSize = 16.sp,
        )
        Spacer(modifier = Modifier.height(12.dp))
        Severity.entries.reversed().forEach { severity ->
            val count = severityCounts[severity] ?: 0
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                SeverityChip(severity = severity)
                Spacer(modifier = Modifier.width(12.dp))
                Text(
                    text = "$count findings",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontSize = 14.sp,
                )
            }
        }
    }
}

@Composable
private fun VulnerabilityCard(vulnerability: Vulnerability) {
    ScanCard(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = vulnerability.title,
                fontWeight = FontWeight.Medium,
                fontSize = 15.sp,
                modifier = Modifier.weight(1f),
            )
            SeverityChip(severity = vulnerability.severity)
        }
        Spacer(modifier = Modifier.height(6.dp))
        Text(
            text = vulnerability.description,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            fontSize = 14.sp,
        )
        Text(
            text = "Category: ${vulnerability.category}",
            color = MaterialTheme.colorScheme.primary,
            fontSize = 12.sp,
            modifier = Modifier.padding(top = 4.dp),
        )
    }
}

private val sampleResult = ScanResult(
    id = "1",
    apkName = "com.example.app-v2.3.apk",
    packageName = "com.example.app",
    versionName = "2.3",
    versionCode = 23,
    overallScore = 72,
    severityCounts = mapOf(
        Severity.SAFE to 12,
        Severity.LOW to 3,
        Severity.MEDIUM to 2,
        Severity.HIGH to 1,
        Severity.CRITICAL to 0,
    ),
    vulnerabilities = listOf(
        Vulnerability(
            id = "v1",
            title = "Insecure Data Storage",
            description = "Application stores sensitive data in SharedPreferences without encryption.",
            severity = Severity.HIGH,
            category = "Data Security",
        ),
        Vulnerability(
            id = "v2",
            title = "Weak Certificate Pinning",
            description = "Certificate pinning is not properly implemented, allowing MITM attacks.",
            severity = Severity.MEDIUM,
            category = "Network Security",
        ),
        Vulnerability(
            id = "v3",
            title = "Exported Activity",
            description = "Activity is exported without proper permission protection.",
            severity = Severity.MEDIUM,
            category = "Component Security",
        ),
    ),
    scanTimestamp = System.currentTimeMillis(),
)
