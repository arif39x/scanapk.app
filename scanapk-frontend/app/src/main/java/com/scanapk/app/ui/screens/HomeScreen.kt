package com.scanapk.app.ui.screens

import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Analytics
import androidx.compose.material.icons.outlined.History
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.scanapk.app.model.ScanResult
import com.scanapk.app.model.Severity
import com.scanapk.app.ui.components.ScanCard
import com.scanapk.app.ui.components.ScanProgressBar
import com.scanapk.app.ui.components.SeverityChip
import com.scanapk.app.ui.theme.OnSurfaceVariant
import com.scanapk.app.ui.theme.Primary

@Composable
fun HomeScreen(
    onNavigateToResult: (String) -> Unit = {},
) {
    var isScanning by remember { mutableStateOf(false) }
    var scanProgress by remember { mutableStateOf(0f) }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        item {
            Spacer(modifier = Modifier.height(8.dp))
            ScanCard {
                Column(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    Text(
                        text = "APK Security Scanner",
                        style = MaterialTheme.typography.headlineSmall,
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "Analyze APK files for vulnerabilities, malware, and security risks",
                        color = OnSurfaceVariant,
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    Spacer(modifier = Modifier.height(24.dp))
                    Button(
                        onClick = {
                            isScanning = true
                            scanProgress = 0f
                        },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(56.dp),
                        shape = RoundedCornerShape(24.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = Primary,
                        ),
                    ) {
                        Icon(
                            imageVector = Icons.Outlined.Analytics,
                            contentDescription = null,
                            modifier = Modifier.size(20.dp),
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = if (isScanning) "Scanning..." else "Start New Scan",
                            fontSize = 16.sp,
                            fontWeight = FontWeight.Medium,
                        )
                    }

                    if (isScanning) {
                        Spacer(modifier = Modifier.height(16.dp))
                        ScanProgressBar(progress = scanProgress)
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = "${(scanProgress * 100).toInt()}%",
                            color = OnSurfaceVariant,
                            fontSize = 13.sp,
                        )
                    }
                }
            }
        }

        item {
            Text(
                text = "Recent Scans",
                style = MaterialTheme.typography.headlineSmall,
                modifier = Modifier.padding(top = 8.dp),
            )
        }

        items(sampleRecentScans) { scan ->
            RecentScanItem(scan = scan, onClick = { onNavigateToResult(scan.id) })
        }

        item {
            Spacer(modifier = Modifier.height(24.dp))
        }
    }
}

@Composable
private fun RecentScanItem(
    scan: ScanResult,
    onClick: () -> Unit,
) {
    ScanCard(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                imageVector = Icons.Outlined.History,
                contentDescription = null,
                tint = OnSurfaceVariant,
                modifier = Modifier.size(20.dp),
            )
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = scan.apkName,
                    fontWeight = FontWeight.Medium,
                    fontSize = 15.sp,
                )
                Text(
                    text = scan.packageName,
                    color = OnSurfaceVariant,
                    fontSize = 13.sp,
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                scan.severityCounts.entries
                    .filter { it.value > 0 && it.key != Severity.SAFE }
                    .sortedByDescending { it.key.score }
                    .take(2)
                    .forEach { (severity, count) ->
                        SeverityChip(severity = severity)
                    }
            }
        }
    }
}

private val sampleRecentScans = listOf(
    ScanResult(
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
