package com.scanapk.app

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.outlined.History
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.IconButton
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.scanapk.app.ui.navigation.AppNavigation
import com.scanapk.app.ui.navigation.Routes
import com.scanapk.app.ui.theme.ScanAPKTheme

class MainActivity : ComponentActivity() {
    private val _intent = mutableStateOf<Intent?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        _intent.value = intent
        setContent {
            val isDarkMode = rememberSaveable { mutableStateOf(false) }
            val useSystemColors = rememberSaveable { mutableStateOf(false) }
            val sharedUri = remember(_intent.value) {
                _intent.value?.let { extractShareUri(it) }
            }
            ScanAPKTheme(
                isDarkMode = isDarkMode.value,
                useSystemColors = useSystemColors.value,
            ) {
                ScanAPKApp(
                    isDarkMode = isDarkMode.value,
                    onToggleDarkMode = { isDarkMode.value = !isDarkMode.value },
                    useSystemColors = useSystemColors.value,
                    onToggleSystemColors = { useSystemColors.value = !useSystemColors.value },
                    initialShareUri = sharedUri,
                )
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        _intent.value = intent
    }

    private fun extractShareUri(intent: Intent): Uri? {
        return when (intent.action) {
            Intent.ACTION_SEND -> intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
            Intent.ACTION_VIEW -> intent.data
            else -> null
        }
    }
}

data class BottomNavItem(
    val label: String,
    val icon: ImageVector,
    val route: String,
)

private val bottomNavItems = listOf(
    BottomNavItem("Home", Icons.Outlined.Home, Routes.HOME),
    BottomNavItem("History", Icons.Outlined.History, Routes.HISTORY),
    BottomNavItem("Settings", Icons.Outlined.Settings, Routes.SETTINGS),
)

private val rootRoutes = listOf(Routes.HOME, Routes.HISTORY, Routes.SETTINGS)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScanAPKApp(
    isDarkMode: Boolean = false,
    onToggleDarkMode: () -> Unit = {},
    useSystemColors: Boolean = false,
    onToggleSystemColors: () -> Unit = {},
    initialShareUri: Uri? = null,
) {
    val navController = rememberNavController()
    val navBackStackEntry by navController.currentBackStackEntryAsState()
    val currentDestination = navBackStackEntry?.destination
    val currentRoute = currentDestination?.route

    val showBottomBar = currentRoute in rootRoutes
    var showAboutDialog by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    var pendingScanUri by remember { mutableStateOf<Uri?>(null) }
    val context = LocalContext.current

    val pickApkLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        uri?.let {
            scope.launch(Dispatchers.IO) {
                try {
                    context.contentResolver.takePersistableUriPermission(
                        it, Intent.FLAG_GRANT_READ_URI_PERMISSION
                    )
                } catch (_: SecurityException) { }
            }
            pendingScanUri = it
            navController.navigate(Routes.SCAN) {
                popUpTo(Routes.HOME)
                launchSingleTop = true
            }
        }
    }

    var initialShareHandled by remember { mutableStateOf(false) }
    LaunchedEffect(initialShareUri) {
        if (initialShareUri != null && !initialShareHandled) {
            pendingScanUri = initialShareUri
            initialShareHandled = true
            navController.navigate(Routes.SCAN) {
                popUpTo(Routes.HOME)
                launchSingleTop = true
            }
        }
    }

    if (showAboutDialog) {
        AlertDialog(
            onDismissRequest = { showAboutDialog = false },
            title = {
                Text(
                    "ScanAPK",
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface,
                )
            },
            text = {
                Column {
                    Text(
                        text = "APK Security Scanner",
                        style = MaterialTheme.typography.headlineSmall,
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "Version 1.0.0",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(modifier = Modifier.height(16.dp))
                    Text(
                        text = "Analyze APK files for vulnerabilities, malware, and security risks. ScanAPK provides comprehensive analysis of Android applications to help identify potential security issues.",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = { showAboutDialog = false }) {
                    Text("Close")
                }
            },
        )
    }

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        containerColor = MaterialTheme.colorScheme.surface,
        topBar = {
            when (currentRoute) {
                Routes.HOME -> {
                    TopAppBar(
                        title = {
                            Text(
                                text = "ScanAPK",
                                fontWeight = FontWeight.Bold,
                                fontSize = 22.sp,
                                color = MaterialTheme.colorScheme.onSurface,
                            )
                        },
                        actions = {
                            IconButton(onClick = { showAboutDialog = true }) {
                                Icon(
                                    imageVector = Icons.Outlined.Info,
                                    contentDescription = "About",
                                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        },
                        colors = TopAppBarDefaults.topAppBarColors(
                            containerColor = MaterialTheme.colorScheme.surface,
                            titleContentColor = MaterialTheme.colorScheme.onSurface,
                        ),
                    )
                }
                Routes.SCAN, Routes.SCAN_RESULT -> {
                    TopAppBar(
                        title = { Text("Scan Results", fontWeight = FontWeight.Bold) },
                        navigationIcon = {
                            IconButton(onClick = { navController.popBackStack() }) {
                                Icon(
                                    imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                                    contentDescription = "Back",
                                )
                            }
                        },
                        colors = TopAppBarDefaults.topAppBarColors(
                            containerColor = MaterialTheme.colorScheme.surface,
                            titleContentColor = MaterialTheme.colorScheme.onSurface,
                        ),
                    )
                }
                Routes.APK_DETAILS -> {
                    TopAppBar(
                        title = { Text("APK Details", fontWeight = FontWeight.Bold) },
                        navigationIcon = {
                            IconButton(onClick = { navController.popBackStack() }) {
                                Icon(
                                    imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                                    contentDescription = "Back",
                                )
                            }
                        },
                        colors = TopAppBarDefaults.topAppBarColors(
                            containerColor = MaterialTheme.colorScheme.surface,
                            titleContentColor = MaterialTheme.colorScheme.onSurface,
                        ),
                    )
                }
                Routes.HISTORY -> {
                    TopAppBar(
                        title = { Text("History", fontWeight = FontWeight.Bold) },
                        colors = TopAppBarDefaults.topAppBarColors(
                            containerColor = MaterialTheme.colorScheme.surface,
                            titleContentColor = MaterialTheme.colorScheme.onSurface,
                        ),
                    )
                }
                Routes.SETTINGS -> {
                    TopAppBar(
                        title = { Text("Settings", fontWeight = FontWeight.Bold) },
                        navigationIcon = {
                            IconButton(onClick = { navController.popBackStack() }) {
                                Icon(
                                    imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                                    contentDescription = "Back",
                                )
                            }
                        },
                        colors = TopAppBarDefaults.topAppBarColors(
                            containerColor = MaterialTheme.colorScheme.surface,
                            titleContentColor = MaterialTheme.colorScheme.onSurface,
                        ),
                    )
                }
            }
        },
        bottomBar = {
            if (showBottomBar) {
                NavigationBar(
                    containerColor = MaterialTheme.colorScheme.surface,
                ) {
                    bottomNavItems.forEach { item ->
                        val selected = currentDestination?.hierarchy?.any { it.route == item.route } == true
                        NavigationBarItem(
                            selected = selected,
                            onClick = {
                                navController.navigate(item.route) {
                                    popUpTo(navController.graph.findStartDestination().id) {
                                        saveState = true
                                    }
                                    launchSingleTop = true
                                    restoreState = true
                                }
                            },
                            icon = {
                                Icon(
                                    imageVector = item.icon,
                                    contentDescription = item.label,
                                )
                            },
                            label = {
                                Text(text = item.label, fontSize = 11.sp)
                            },
                            colors = NavigationBarItemDefaults.colors(
                                selectedIconColor = MaterialTheme.colorScheme.primary,
                                selectedTextColor = MaterialTheme.colorScheme.primary,
                                unselectedIconColor = MaterialTheme.colorScheme.onSurfaceVariant,
                                unselectedTextColor = MaterialTheme.colorScheme.onSurfaceVariant,
                                indicatorColor = MaterialTheme.colorScheme.surface,
                            ),
                        )
                    }
                }
            }
        },
    ) { padding ->
        AppNavigation(
            navController = navController,
            isDarkMode = isDarkMode,
            onToggleDarkMode = onToggleDarkMode,
            useSystemColors = useSystemColors,
            onToggleSystemColors = onToggleSystemColors,
            pendingScanUri = pendingScanUri,
            onScanRequested = {
                pickApkLauncher.launch(arrayOf(
                    "application/vnd.android.package-archive",
                    "application/octet-stream",
                    "*/*"
                ))
            },
            modifier = Modifier.padding(padding),
        )
    }
}
