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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.Dangerous
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.scanapk.app.model.ApkInfo
import com.scanapk.app.model.Permission
import com.scanapk.app.ui.components.DataTable
import com.scanapk.app.ui.components.ScanCard
import com.scanapk.app.ui.components.TableRow
import com.scanapk.app.ui.theme.OnSurfaceVariant
import com.scanapk.app.ui.theme.SeverityHigh
import com.scanapk.app.ui.theme.SeveritySafe

@Composable
fun ApkDetailsScreen(
    apkInfo: ApkInfo = sampleApkInfo,
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        item {
            Spacer(modifier = Modifier.height(8.dp))
            ScanCard(modifier = Modifier.fillMaxWidth()) {
                Text(
                    text = apkInfo.appName,
                    style = MaterialTheme.typography.headlineSmall,
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = apkInfo.packageName,
                    color = OnSurfaceVariant,
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }

        item {
            ScanCard(modifier = Modifier.fillMaxWidth()) {
                Text(
                    text = "Metadata",
                    fontWeight = FontWeight.Bold,
                    fontSize = 16.sp,
                )
                Spacer(modifier = Modifier.height(12.dp))
                DataTable(
                    rows = listOf(
                        TableRow("Version", "${apkInfo.versionName} (${apkInfo.versionCode})"),
                        TableRow("Min SDK", "API ${apkInfo.minSdk}"),
                        TableRow("Target SDK", "API ${apkInfo.targetSdk}"),
                        TableRow("File Size", formatFileSize(apkInfo.fileSize)),
                    ),
                )
            }
        }

        item {
            ScanCard(modifier = Modifier.fillMaxWidth()) {
                Text(
                    text = "Hashes",
                    fontWeight = FontWeight.Bold,
                    fontSize = 16.sp,
                )
                Spacer(modifier = Modifier.height(12.dp))
                DataTable(
                    rows = listOf(
                        TableRow("SHA-256", apkInfo.sha256),
                        TableRow("MD5", apkInfo.md5),
                    ),
                )
            }
        }

        item {
            Text(
                text = "Permissions",
                style = MaterialTheme.typography.headlineSmall,
            )
        }

        items(apkInfo.permissions) { permission ->
            PermissionItem(permission = permission)
        }

        item {
            Spacer(modifier = Modifier.height(24.dp))
        }
    }
}

@Composable
private fun PermissionItem(permission: Permission) {
    ScanCard(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                imageVector = if (permission.isDangerous) Icons.Outlined.Dangerous else Icons.Outlined.CheckCircle,
                contentDescription = null,
                tint = if (permission.isDangerous) SeverityHigh else SeveritySafe,
                modifier = Modifier.size(20.dp),
            )
            Spacer(modifier = Modifier.width(10.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = permission.name,
                    fontWeight = FontWeight.Medium,
                    fontSize = 14.sp,
                )
                Text(
                    text = permission.description,
                    color = OnSurfaceVariant,
                    fontSize = 12.sp,
                )
            }
            if (permission.isDangerous) {
                Icon(
                    imageVector = Icons.Outlined.Info,
                    contentDescription = "Dangerous",
                    tint = SeverityHigh,
                    modifier = Modifier.size(16.dp),
                )
            }
        }
    }
}

private fun formatFileSize(bytes: Long): String {
    return when {
        bytes >= 1_073_741_824 -> "%.2f GB".format(bytes / 1_073_741_824.0)
        bytes >= 1_048_576 -> "%.2f MB".format(bytes / 1_048_576.0)
        bytes >= 1_024 -> "%.2f KB".format(bytes / 1_024.0)
        else -> "$bytes bytes"
    }
}

private val sampleApkInfo = ApkInfo(
    packageName = "com.example.app",
    appName = "Example App",
    versionName = "2.3",
    versionCode = 23,
    minSdk = 26,
    targetSdk = 34,
    sha256 = "a3f8b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0",
    md5 = "e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6",
    fileSize = 4_194_304,
    permissions = listOf(
        Permission("android.permission.INTERNET", "Access network resources", false),
        Permission("android.permission.ACCESS_FINE_LOCATION", "Access precise location", true),
        Permission("android.permission.CAMERA", "Access camera device", true),
        Permission("android.permission.READ_EXTERNAL_STORAGE", "Read from external storage", true),
        Permission("android.permission.ACCESS_NETWORK_STATE", "View network state", false),
    ),
)
