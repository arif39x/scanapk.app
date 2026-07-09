package com.scanapk.app.ui.screens

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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.TrackChanges
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.scanapk.app.model.ScanResult
import com.scanapk.app.model.Severity
import com.scanapk.app.model.Vulnerability
import com.scanapk.app.ui.components.ScanCard
import com.scanapk.app.ui.components.ScanProgressBar
import com.scanapk.app.ui.components.SeverityChip
import com.scanapk.app.ui.theme.SeverityCritical
import com.scanapk.app.ui.theme.SeverityHigh
import com.scanapk.app.ui.theme.SeverityLow
import com.scanapk.app.ui.theme.SeverityMedium
import com.scanapk.app.ui.theme.SeveritySafe
import com.scanapk.app.viewmodel.ScanViewModel

@Composable
fun ScanResultScreen(
    scanResult: ScanResult = sampleResult,
    apkUri: Uri? = null,
) {
    val viewModel: ScanViewModel = viewModel()
    val context = LocalContext.current
    val isScanning by viewModel.isScanning.collectAsState()
    val scannedResult by viewModel.scannedResult.collectAsState()
    val errorMessage by viewModel.errorMessage.collectAsState()
    val copyProgress by viewModel.copyProgress.collectAsState()
    val currentStatus by viewModel.currentStatus.collectAsState()

    LaunchedEffect(apkUri) {
        if (apkUri != null) {
            viewModel.scan(context, apkUri)
        }
    }

    val displayResult = scannedResult ?: scanResult

    if (isScanning) {
        Box(
            modifier = Modifier.fillMaxSize(),
            contentAlignment = Alignment.Center,
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                if (copyProgress >= 0f) {
                    ScanProgressBar(
                        progress = copyProgress,
                        modifier = Modifier
                            .fillMaxWidth(0.7f)
                            .padding(bottom = 16.dp),
                        height = 6.dp,
                    )
                    Text(
                        text = "Uploading... ${(copyProgress * 100).toInt()}%",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Spacer(modifier = Modifier.height(16.dp))
                }
                CircularProgressIndicator(
                    modifier = Modifier.size(48.dp),
                    color = MaterialTheme.colorScheme.primary,
                )
                Spacer(modifier = Modifier.height(16.dp))
                Text(
                    text = currentStatus.ifEmpty { "Scanning..." },
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
                VerdictCard(scanResult = displayResult)
            }

            if (displayResult.keyFindings.isNotEmpty()) {
                item {
                    FindingsCard(findings = displayResult.keyFindings)
                }
            }

            item {
                FindingCountsGrid(scanResult = displayResult)
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

            if (displayResult.recommendations.isNotEmpty()) {
                item {
                    RecommendationsCard(recommendations = displayResult.recommendations)
                }
            }

            item {
                Spacer(modifier = Modifier.height(24.dp))
            }
        }
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
                text = "Security Score / 100",
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
private fun VerdictCard(scanResult: ScanResult) {
    ScanCard(modifier = Modifier.fillMaxWidth()) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                imageVector = Icons.Filled.Shield,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(24.dp),
            )
            Spacer(modifier = Modifier.width(12.dp))
            Column {
                Text(
                    text = "Verdict: ${scanResult.verdict}",
                    fontWeight = FontWeight.Bold,
                    fontSize = 16.sp,
                )
                Text(
                    text = "Severity: ${scanResult.severity}",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontSize = 14.sp,
                )
                scanResult.malwareFamily?.let {
                    Text(
                        text = "Family: $it",
                        color = MaterialTheme.colorScheme.error,
                        fontSize = 14.sp,
                    )
                }
            }
        }
    }
}

@Composable
private fun FindingsCard(findings: List<String>) {
    ScanCard(modifier = Modifier.fillMaxWidth()) {
        Text(
            text = "Key Findings",
            fontWeight = FontWeight.Bold,
            fontSize = 16.sp,
        )
        Spacer(modifier = Modifier.height(8.dp))
        findings.forEach { finding ->
            Row(modifier = Modifier.padding(vertical = 2.dp)) {
                Text("•  ", color = MaterialTheme.colorScheme.primary)
                Text(
                    text = finding,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontSize = 13.sp,
                )
            }
        }
    }
}

@Composable
private fun FindingCountsGrid(scanResult: ScanResult) {
    ScanCard(modifier = Modifier.fillMaxWidth()) {
        Text(
            text = "Analysis Summary",
            fontWeight = FontWeight.Bold,
            fontSize = 16.sp,
        )
        Spacer(modifier = Modifier.height(12.dp))
        FindingRow(Icons.Filled.Warning, "Dangerous Permissions", scanResult.dangerousPermissionCount, SeverityHigh)
        FindingRow(Icons.Filled.Code, "Suspicious APIs", scanResult.suspiciousApiCount, SeverityHigh)
        FindingRow(Icons.Filled.BugReport, "YARA Rule Matches", scanResult.yaraMatchCount, SeverityCritical)
        FindingRow(Icons.Filled.TrackChanges, "Trackers Detected", scanResult.trackerCount, SeverityMedium)
        FindingRow(Icons.Filled.Link, "Embedded URLs", scanResult.urlCount, SeverityMedium)
        FindingRow(Icons.Filled.Dns, "Embedded IPs", scanResult.ipCount, SeverityMedium)
        FindingRow(Icons.Filled.Lock, "Native Libraries", scanResult.nativeLibCount, SeverityLow)
    }
}

@Composable
private fun FindingRow(icon: ImageVector, label: String, count: Int, defaultColor: androidx.compose.ui.graphics.Color) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = if (count > 0) defaultColor else MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f),
            modifier = Modifier.size(18.dp),
        )
        Spacer(modifier = Modifier.width(12.dp))
        Text(
            text = label,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            fontSize = 14.sp,
            modifier = Modifier.weight(1f),
        )
        Text(
            text = "$count",
            fontWeight = FontWeight.Bold,
            fontSize = 14.sp,
            color = if (count > 0) defaultColor else MaterialTheme.colorScheme.onSurfaceVariant,
        )
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

@Composable
private fun RecommendationsCard(recommendations: List<String>) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.secondaryContainer,
        ),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = "Recommendations",
                fontWeight = FontWeight.Bold,
                fontSize = 16.sp,
            )
            Spacer(modifier = Modifier.height(8.dp))
            recommendations.forEach { rec ->
                Row(modifier = Modifier.padding(vertical = 2.dp)) {
                    Text("→  ", color = MaterialTheme.colorScheme.onSecondaryContainer)
                    Text(
                        text = rec,
                        color = MaterialTheme.colorScheme.onSecondaryContainer,
                        fontSize = 13.sp,
                    )
                }
            }
        }
    }
}

private val sampleResult = ScanResult(
    id = "1",
    apkName = "com.example.app-v2.3.apk",
    packageName = "com.example.app",
    versionName = "2.3",
    versionCode = 23,
    overallScore = 72,
    severity = "LOW",
    verdict = "REVIEW",
    malwareFamily = null,
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
