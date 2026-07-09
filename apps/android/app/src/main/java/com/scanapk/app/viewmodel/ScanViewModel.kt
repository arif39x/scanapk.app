package com.scanapk.app.viewmodel

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.scanapk.app.model.ScanHistory
import com.scanapk.app.model.ScanResult
import com.scanapk.app.model.Severity
import com.scanapk.app.model.Vulnerability
import com.scanapk.app.network.ApiClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.MultipartBody
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.File
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

    private val _currentStatus = MutableStateFlow("")
    val currentStatus: StateFlow<String> = _currentStatus.asStateFlow()

    private var currentUri: Uri? = null
    private var pollingJob: Job? = null

    fun scan(context: Context, uri: Uri) {
        if (_isScanning.value) return
        if (uri == currentUri && _scannedResult.value != null) return
        currentUri = uri

        viewModelScope.launch {
            _isScanning.value = true
            _errorMessage.value = null
            _scannedResult.value = null
            _copyProgress.value = -1f
            _currentStatus.value = "Preparing APK..."

            try {
                val tempFile = withContext(Dispatchers.IO) {
                    copyApkToCache(context, uri)
                }

                if (tempFile == null) {
                    _errorMessage.value = "Failed to read APK file"
                    return@launch
                }

                _currentStatus.value = "Uploading to server..."

                val jobId = withContext(Dispatchers.IO) {
                    uploadApk(tempFile)
                }

                if (jobId == null) {
                    _errorMessage.value = "Failed to upload APK"
                    return@launch
                }

                _currentStatus.value = "Analysis in progress..."

                val result = withContext(Dispatchers.IO) {
                    pollForResult(jobId)
                }

                if (result != null) {
                    _scannedResult.value = result
                    ScanHistory.addScan(result)
                } else {
                    _errorMessage.value = "Analysis failed or timed out"
                }
            } catch (e: Exception) {
                e.printStackTrace()
                _errorMessage.value = "Scan failed: ${e.localizedMessage ?: "Unknown error"}"
            } finally {
                _isScanning.value = false
                _currentStatus.value = ""
            }
        }
    }

    private suspend fun copyApkToCache(context: Context, uri: Uri): File? {
        val tempFile = File(context.cacheDir, "upload_${System.currentTimeMillis()}.apk")
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
            return tempFile
        } catch (e: Exception) {
            tempFile.delete()
            return null
        }
    }

    private suspend fun uploadApk(file: File): String? {
        return try {
            val requestBody = file.readBytes()
                .toRequestBody("application/vnd.android.package-archive".toMediaTypeOrNull())
            val part = MultipartBody.Part.createFormData("apk", file.name, requestBody)
            val response = ApiClient.scanApi.uploadApk(part)
            file.delete()
            response.jobId
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    private suspend fun pollForResult(jobId: String): ScanResult? {
        var attempts = 0
        val maxAttempts = 120

        while (attempts < maxAttempts) {
            try {
                val status = ApiClient.scanApi.getStatus(jobId)
                when (status.status) {
                    "completed" -> {
                        return fetchReport(jobId)
                    }
                    "failed" -> {
                        _errorMessage.value = status.error ?: "Analysis failed"
                        return null
                    }
                    "running" -> {
                        _currentStatus.value = "Analyzing..."
                    }
                    "pending" -> {
                        _currentStatus.value = "Queued..."
                    }
                }
            } catch (e: Exception) {
                _errorMessage.value = "Connection error: ${e.localizedMessage}"
                return null
            }

            attempts++
            delay(2000)
        }

        _errorMessage.value = "Analysis timed out"
        return null
    }

    private suspend fun fetchReport(jobId: String): ScanResult? {
        return try {
            val summary = ApiClient.scanApi.getReportSummary(jobId)

            val overallScore = summary.assessment?.riskScore ?: 0

            val severity = summary.assessment?.severity ?: "UNKNOWN"
            val verdict = summary.verdict ?: "UNKNOWN"
            val malwareFamily = summary.assessment?.malwareFamily

            val keyFindings = summary.assessment?.keyFindings ?: emptyList()
            val recommendations = summary.assessment?.recommendations ?: emptyList()
            val threatTypes = summary.assessment?.threatTypes ?: emptyList()

            val scoreBreakdown = summary.assessment?.scoreBreakdown ?: emptyMap()

            val dangerousPermCount = summary.summary?.dangerousPermissionCount ?: 0
            val yaraCount = summary.summary?.yaraMatchCount ?: 0
            val apiCount = summary.summary?.suspiciousApiCount ?: 0
            val trackerCount = summary.summary?.trackerCount ?: 0
            val urlCount = summary.summary?.urlCount ?: 0
            val ipCount = summary.summary?.ipCount ?: 0
            val nativeCount = summary.summary?.nativeLibCount ?: 0
            val exfilCount = summary.summary?.exfiltrationChainCount ?: 0

            val packageName = summary.app?.packageName ?: "unknown"
            val appName = summary.app?.name ?: packageName

            val severityMap = mapOf(
                Severity.CRITICAL to if (overallScore >= 81) 1 else 0,
                Severity.HIGH to if (overallScore in 61..80) 1 else 0,
                Severity.MEDIUM to if (overallScore in 41..60) 1 else 0,
                Severity.LOW to if (overallScore in 21..40) 1 else 0,
                Severity.SAFE to if (overallScore <= 20) 1 else 0,
            )

            ScanResult(
                id = jobId,
                apkName = summary.app?.name ?: "${packageName}.apk",
                packageName = packageName,
                versionName = "",
                versionCode = 0,
                overallScore = overallScore,
                severity = severity,
                verdict = verdict,
                malwareFamily = malwareFamily,
                severityCounts = severityMap,
                vulnerabilities = buildVulnerabilityList(summary, keyFindings),
                keyFindings = keyFindings,
                recommendations = recommendations,
                threatTypes = threatTypes,
                scanTimestamp = System.currentTimeMillis(),
                yaraMatchCount = yaraCount,
                suspiciousApiCount = apiCount,
                trackerCount = trackerCount,
                urlCount = urlCount,
                ipCount = ipCount,
                nativeLibCount = nativeCount,
                dangerousPermissionCount = dangerousPermCount,
                exfiltrationChainCount = exfilCount,
                scoreBreakdown = scoreBreakdown,
            )
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    private fun buildVulnerabilityList(
        summary: com.scanapk.app.network.ScanSummaryResponse,
        keyFindings: List<String>,
    ): List<Vulnerability> {
        val vulns = mutableListOf<Vulnerability>()

        keyFindings.forEach { finding ->
            val sev = when {
                finding.contains("CRITICAL", ignoreCase = true) -> Severity.CRITICAL
                finding.contains("HIGH", ignoreCase = true) -> Severity.HIGH
                finding.contains("MEDIUM", ignoreCase = true) -> Severity.MEDIUM
                finding.contains("LOW", ignoreCase = true) || finding.contains("CLEAN", ignoreCase = true) -> Severity.LOW
                else -> Severity.MEDIUM
            }
            vulns.add(
                Vulnerability(
                    id = UUID.randomUUID().toString(),
                    title = finding.take(80),
                    description = finding,
                    severity = sev,
                    category = "Finding",
                )
            )
        }

        return vulns
    }

    fun reset() {
        _scannedResult.value = null
        _errorMessage.value = null
        _copyProgress.value = -1f
        _currentStatus.value = ""
        currentUri = null
        pollingJob?.cancel()
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

    private suspend fun copyWithProgress(input: java.io.InputStream, output: java.io.OutputStream, totalBytes: Long) {
        val buffer = ByteArray(8192)
        var bytesRead: Int
        var totalRead = 0L
        while (input.read(buffer).also { bytesRead = it } != -1) {
            output.write(buffer, 0, bytesRead)
            totalRead += bytesRead
            _copyProgress.value = (totalRead.toFloat() / totalBytes).coerceIn(0f, 1f)
        }
    }
}
