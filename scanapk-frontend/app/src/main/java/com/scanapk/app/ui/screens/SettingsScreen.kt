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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.BugReport
import androidx.compose.material.icons.outlined.DarkMode
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Notifications
import androidx.compose.material.icons.outlined.Palette
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.Storage
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.scanapk.app.ui.components.ScanCard
import com.scanapk.app.ui.theme.OnSurface
import com.scanapk.app.ui.theme.OnSurfaceVariant
import com.scanapk.app.ui.theme.Primary
import com.scanapk.app.ui.theme.Surface

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    onBack: () -> Unit = {},
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Settings", fontWeight = FontWeight.Bold) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = "Back",
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Surface,
                    titleContentColor = OnSurface,
                ),
            )
        },
        containerColor = Surface,
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            item {
                Spacer(modifier = Modifier.height(8.dp))
            }

            item {
                ScanCard(modifier = Modifier.fillMaxWidth()) {
                    Text(
                        text = "Scan Configuration",
                        fontWeight = FontWeight.Bold,
                        fontSize = 16.sp,
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    SettingToggle(
                        icon = Icons.Outlined.Notifications,
                        title = "Notifications",
                        subtitle = "Get notified when scan completes",
                        checked = true,
                    )
                    SettingToggle(
                        icon = Icons.Outlined.Storage,
                        title = "Auto-save Reports",
                        subtitle = "Save scan reports locally",
                        checked = true,
                    )
                    SettingToggle(
                        icon = Icons.Outlined.BugReport,
                        title = "Deep Analysis",
                        subtitle = "Perform thorough malware analysis",
                        checked = false,
                    )
                }
            }

            item {
                ScanCard(modifier = Modifier.fillMaxWidth()) {
                    Text(
                        text = "Appearance",
                        fontWeight = FontWeight.Bold,
                        fontSize = 16.sp,
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    SettingToggle(
                        icon = Icons.Outlined.DarkMode,
                        title = "Dark Theme",
                        subtitle = "Use dark color scheme",
                        checked = false,
                    )
                    SettingToggle(
                        icon = Icons.Outlined.Palette,
                        title = "Dynamic Colors",
                        subtitle = "Use Material You color theme",
                        checked = true,
                    )
                }
            }

            item {
                ScanCard(modifier = Modifier.fillMaxWidth()) {
                    Text(
                        text = "About",
                        fontWeight = FontWeight.Bold,
                        fontSize = 16.sp,
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    AboutRow(icon = Icons.Outlined.Security, title = "ScanAPK", subtitle = "Version 1.0.0")
                    AboutRow(icon = Icons.Outlined.Info, title = "Security Scanner", subtitle = "APK Analysis Tool")
                }
            }

            item {
                Spacer(modifier = Modifier.height(24.dp))
            }
        }
    }
}

@Composable
private fun SettingToggle(
    icon: ImageVector,
    title: String,
    subtitle: String,
    checked: Boolean,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = OnSurfaceVariant,
            modifier = Modifier.size(22.dp),
        )
        Spacer(modifier = Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                fontWeight = FontWeight.Medium,
                fontSize = 15.sp,
            )
            Text(
                text = subtitle,
                color = OnSurfaceVariant,
                fontSize = 13.sp,
            )
        }
        Switch(
            checked = checked,
            onCheckedChange = {},
            colors = SwitchDefaults.colors(
                checkedTrackColor = Primary,
            ),
        )
    }
}

@Composable
private fun AboutRow(
    icon: ImageVector,
    title: String,
    subtitle: String,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = Primary,
            modifier = Modifier.size(22.dp),
        )
        Spacer(modifier = Modifier.width(12.dp))
        Column {
            Text(
                text = title,
                fontWeight = FontWeight.Medium,
                fontSize = 15.sp,
            )
            Text(
                text = subtitle,
                color = OnSurfaceVariant,
                fontSize = 13.sp,
            )
        }
    }
}
