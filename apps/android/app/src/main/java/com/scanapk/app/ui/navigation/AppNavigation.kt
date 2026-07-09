package com.scanapk.app.ui.navigation

import android.net.Uri
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.scanapk.app.ui.screens.ApkDetailsScreen
import com.scanapk.app.ui.screens.HistoryScreen
import com.scanapk.app.ui.screens.HomeScreen
import com.scanapk.app.ui.screens.ScanResultScreen
import com.scanapk.app.ui.screens.SettingsScreen

object Routes {
    const val HOME = "home"
    const val HISTORY = "history"
    const val SCAN = "scan"
    const val SCAN_RESULT = "scan_result/{scanId}"
    const val APK_DETAILS = "apk_details"
    const val SETTINGS = "settings"

    fun scanResult(scanId: String) = "scan_result/$scanId"
}

@Composable
fun AppNavigation(
    navController: NavHostController,
    isDarkMode: Boolean = false,
    onToggleDarkMode: () -> Unit = {},
    useSystemColors: Boolean = false,
    onToggleSystemColors: () -> Unit = {},
    pendingScanUri: Uri? = null,
    onScanRequested: () -> Unit = {},
    modifier: Modifier = Modifier,
) {
    NavHost(
        navController = navController,
        startDestination = Routes.HOME,
        modifier = modifier,
    ) {
        composable(Routes.HOME) {
            HomeScreen(
                onNavigateToResult = { scanId ->
                    navController.navigate(Routes.scanResult(scanId))
                },
                onScanRequested = onScanRequested,
            )
        }

        composable(Routes.HISTORY) {
            HistoryScreen(
                onNavigateToResult = { scanId ->
                    navController.navigate(Routes.scanResult(scanId))
                },
            )
        }

        composable(Routes.SCAN) {
            ScanResultScreen(
                apkUri = pendingScanUri,
            )
        }

        composable(
            route = Routes.SCAN_RESULT,
            arguments = listOf(navArgument("scanId") { type = NavType.StringType }),
        ) {
            ScanResultScreen()
        }

        composable(Routes.APK_DETAILS) {
            ApkDetailsScreen()
        }

        composable(Routes.SETTINGS) {
            SettingsScreen(
                isDarkMode = isDarkMode,
                onToggleDarkMode = onToggleDarkMode,
                useSystemColors = useSystemColors,
                onToggleSystemColors = onToggleSystemColors,
            )
        }
    }
}
