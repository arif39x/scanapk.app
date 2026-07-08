package com.scanapk.app.viewmodel

import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.OpenableColumns
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.scanapk.app.model.ScanHistory
import com.scanapk.app.model.ScanResult
import com.scanapk.app.model.Severity
import com.scanapk.app.model.Vulnerability
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.util.UUID

class ScanViewModel : ViewModel() {
    private val _isScanning = MutableStateFlow(false)
    val isScanning: StateFlow<Boolean> = _isScanning.asStateFlow()

    private val _scannedResult = MutableStateFlow<ScanResult?>(null)
    val scannedResult: StateFlow<ScanResult?> = _scannedResult.asStateFlow()

    private val _errorMessage = MutableStateFlow<String?>(null)
    val errorMessage: StateFlow<String?> = _errorMessage.asStateFlow()

    private val _copyProgress = MutableStateFlow(-1f)
    val copyProgress: StateFlow<Float> = _copyProgress.asStateFlow()

    private var currentUri: Uri? = null

    fun scan(context: Context, uri: Uri) {
        if (_isScanning.value) return
        if (uri == currentUri && _scannedResult.value != null) return
        currentUri = uri

        viewModelScope.launch {
            _isScanning.value = true
            _errorMessage.value = null
            _scannedResult.value = null
            _copyProgress.value = -1f

            try {
                val result = withContext(Dispatchers.IO) {
                    scanApkInternal(context, uri)
                }
                if (result != null) {
                    _scannedResult.value = result
                    ScanHistory.addScan(result)
                } else {
                    _errorMessage.value = "Failed to scan APK. The file may be invalid or inaccessible."
                }
            } catch (e: Exception) {
                e.printStackTrace()
                _errorMessage.value = "Scan failed: ${e.localizedMessage ?: "Unknown error"}"
            } finally {
                _isScanning.value = false
            }
        }
    }

    fun reset() {
        _scannedResult.value = null
        _errorMessage.value = null
        _copyProgress.value = -1f
        currentUri = null
    }

    @Suppress("DEPRECATION")
    private suspend fun scanApkInternal(context: Context, uri: Uri): ScanResult? {
        val tempFile = File(context.cacheDir, "scan_${System.currentTimeMillis()}.apk")
        try {
            val fileSize = getFileSize(context, uri)
            val inputStream = context.contentResolver.openInputStream(uri) ?: return null

            inputStream.use { input ->
                tempFile.outputStream().use { output ->
                    if (fileSize > 0) {
                        copyWithProgress(input, output, fileSize)
                    } else {
                        input.copyTo(output)
                    }
                }
            }

            val pm = context.packageManager
            val pi = pm.getPackageArchiveInfo(
                tempFile.absolutePath,
                PackageManager.GET_ACTIVITIES or PackageManager.GET_PERMISSIONS
            ) ?: return null

            val pkgName = pi.packageName
            val versionName = pi.versionName ?: "1.0"
            val versionCode = pi.versionCode
            val apkName = "${pkgName}-v${versionName}.apk"

            val manifestPerms = pi.requestedPermissions ?: emptyArray()
            val vulnerabilities = mutableListOf<Vulnerability>()

            manifestPerms.forEach { perm ->
                when {
                    perm == "android.permission.READ_CONTACTS" || perm == "android.permission.WRITE_CONTACTS" ->
                        vulnerabilities.add(vuln("Reads Contacts", "Application requests permission to read user contacts, which may pose a privacy risk.", Severity.MEDIUM, "Privacy"))
                    perm == "android.permission.CAMERA" ->
                        vulnerabilities.add(vuln("Camera Access", "Application requests camera access, which could be used for unauthorized recording.", Severity.MEDIUM, "Privacy"))
                    perm == "android.permission.RECORD_AUDIO" ->
                        vulnerabilities.add(vuln("Audio Recording", "Application can record audio without user interaction.", Severity.HIGH, "Privacy"))
                    perm == "android.permission.ACCESS_FINE_LOCATION" || perm == "android.permission.ACCESS_COARSE_LOCATION" ->
                        vulnerabilities.add(vuln("Location Tracking", "Application can access device location, potentially tracking user movement.", Severity.HIGH, "Privacy"))
                    perm == "android.permission.SEND_SMS" || perm == "android.permission.RECEIVE_SMS" || perm == "android.permission.READ_SMS" ->
                        vulnerabilities.add(vuln("SMS Access", "Application can read or intercept SMS messages, potentially capturing sensitive information.", Severity.CRITICAL, "Privacy"))
                    perm == "android.permission.READ_PHONE_STATE" ->
                        vulnerabilities.add(vuln("Phone State Access", "Application can access device identifiers like IMEI, which can be used for device tracking.", Severity.MEDIUM, "Privacy"))
                    perm == "android.permission.READ_CALENDAR" || perm == "android.permission.WRITE_CALENDAR" ->
                        vulnerabilities.add(vuln("Calendar Access", "Application can read calendar events, potentially accessing personal schedule information.", Severity.MEDIUM, "Privacy"))
                    perm == "android.permission.BODY_SENSORS" ->
                        vulnerabilities.add(vuln("Body Sensor Access", "Application can access sensor data like heart rate, potentially exposing health information.", Severity.MEDIUM, "Privacy"))
                    perm == "android.permission.ACTIVITY_RECOGNITION" ->
                        vulnerabilities.add(vuln("Activity Recognition", "Application can recognize user activity patterns, potentially inferring behavior.", Severity.LOW, "Privacy"))
                }
            }

            val appFlags = pi.applicationInfo?.flags ?: 0
            val isDebuggable = appFlags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE != 0
            if (isDebuggable) {
                vulnerabilities.add(vuln("Debuggable Application", "The APK is built in debug mode, which should not be used for production releases.", Severity.HIGH, "Code Quality"))
            }

            val severityCounts = mutableMapOf(
                Severity.SAFE to 0, Severity.LOW to 0, Severity.MEDIUM to 0,
                Severity.HIGH to 0, Severity.CRITICAL to 0,
            )
            var safeCount = manifestPerms.size
            vulnerabilities.forEach { vuln ->
                severityCounts[vuln.severity] = (severityCounts[vuln.severity] ?: 0) + 1
                safeCount--
            }
            severityCounts[Severity.SAFE] = maxOf(0, safeCount)

            val deductions = vulnerabilities.fold(0) { acc, vuln ->
                acc + when (vuln.severity) {
                    Severity.LOW -> 5
                    Severity.MEDIUM -> 10
                    Severity.HIGH -> 20
                    Severity.CRITICAL -> 35
                    else -> 0
                }
            }
            val overallScore = maxOf(0, 100 - deductions)

            return ScanResult(
                id = UUID.randomUUID().toString(),
                apkName = apkName,
                packageName = pkgName,
                versionName = versionName,
                versionCode = versionCode,
                overallScore = overallScore,
                severityCounts = severityCounts.toMap(),
                vulnerabilities = vulnerabilities,
                scanTimestamp = System.currentTimeMillis(),
            )
        } finally {
            if (tempFile.exists()) {
                tempFile.delete()
            }
        }
    }

    private fun getFileSize(context: Context, uri: Uri): Long {
        try {
            context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val idx = cursor.getColumnIndex(OpenableColumns.SIZE)
                    if (idx >= 0 && !cursor.isNull(idx)) {
                        return cursor.getLong(idx)
                    }
                }
            }
        } catch (_: Exception) { }
        try {
            context.contentResolver.openFileDescriptor(uri, "r")?.use { fd ->
                return fd.statSize
            }
        } catch (_: Exception) { }
        return -1
    }

    private suspend fun copyWithProgress(input: InputStream, output: OutputStream, totalBytes: Long) {
        val buffer = ByteArray(8192)
        var bytesRead: Int
        var totalRead = 0L
        while (input.read(buffer).also { bytesRead = it } != -1) {
            output.write(buffer, 0, bytesRead)
            totalRead += bytesRead
            _copyProgress.value = (totalRead.toFloat() / totalBytes).coerceIn(0f, 1f)
        }
    }

    private fun vuln(title: String, description: String, severity: Severity, category: String) =
        Vulnerability(id = UUID.randomUUID().toString(), title = title, description = description, severity = severity, category = category)
}
