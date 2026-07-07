package com.scanapk.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.sp
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.scanapk.app.ui.navigation.AppNavigation
import com.scanapk.app.ui.navigation.Routes
import com.scanapk.app.ui.theme.OnSurfaceVariant
import com.scanapk.app.ui.theme.Primary
import com.scanapk.app.ui.theme.ScanAPKTheme
import com.scanapk.app.ui.theme.Surface
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Settings

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            ScanAPKTheme {
                ScanAPKApp()
            }
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
    BottomNavItem("Details", Icons.Outlined.Info, Routes.APK_DETAILS),
    BottomNavItem("Settings", Icons.Outlined.Settings, Routes.SETTINGS),
)

@Composable
fun ScanAPKApp() {
    val navController = rememberNavController()
    val navBackStackEntry by navController.currentBackStackEntryAsState()
    val currentDestination = navBackStackEntry?.destination

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        containerColor = Surface,
        bottomBar = {
            NavigationBar(
                containerColor = Surface,
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
                            selectedIconColor = Primary,
                            selectedTextColor = Primary,
                            unselectedIconColor = OnSurfaceVariant,
                            unselectedTextColor = OnSurfaceVariant,
                            indicatorColor = Surface,
                        ),
                    )
                }
            }
        },
    ) { padding ->
        AppNavigation(
            navController = navController,
            modifier = Modifier.padding(padding),
        )
    }
}
