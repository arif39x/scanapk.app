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
                        text = "Copying APK... ${(copyProgress * 100).toInt()}%",
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
                    text = if (copyProgress >= 0f) "Analyzing APK..." else "Scanning APK...",
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
