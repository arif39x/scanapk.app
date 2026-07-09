package com.scanapk.app.model

data class Permission(
    val name: String,
    val description: String,
    val isDangerous: Boolean,
)

data class ApkInfo(
    val packageName: String,
    val appName: String,
    val versionName: String,
    val versionCode: Int,
    val minSdk: Int,
    val targetSdk: Int,
    val sha256: String,
    val md5: String,
    val fileSize: Long,
    val permissions: List<Permission>,
)
