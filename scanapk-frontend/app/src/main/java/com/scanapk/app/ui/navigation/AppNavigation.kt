package com.scanapk.app.ui.navigation

import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import com.scanapk.app.ui.screens.ApkDetailsScreen
import com.scanapk.app.ui.screens.HomeScreen
import com.scanapk.app.ui.screens.ScanResultScreen
import com.scanapk.app.ui.screens.SettingsScreen

object Routes {
    const val HOME = "home"
    const val SCAN_RESULT = "scan_result/{scanId}"
    const val APK_DETAILS = "apk_details"
    const val SETTINGS = "settings"

    fun scanResult(scanId: String) = "scan_result/$scanId"
}

@Composable
fun AppNavigation(
    navController: NavHostController,
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
                onNavigateToApkDetails = {
                    navController.navigate(Routes.APK_DETAILS)
                },
            )
        }

        composable(Routes.SCAN_RESULT) {
            ScanResultScreen(
                onBack = { navController.popBackStack() },
            )
        }

        composable(Routes.APK_DETAILS) {
            ApkDetailsScreen(
                onBack = { navController.popBackStack() },
            )
        }

        composable(Routes.SETTINGS) {
            SettingsScreen(
                onBack = { navController.popBackStack() },
            )
        }
    }
}
