package com.scanapk.app.network

import com.google.gson.annotations.SerializedName

data class ScanJobResponse(
    @SerializedName("job_id") val jobId: String? = null,
    val status: String? = null,
    val filename: String? = null,
    @SerializedName("created_at") val createdAt: String? = null,
    @SerializedName("started_at") val startedAt: String? = null,
    @SerializedName("completed_at") val completedAt: String? = null,
    val result: ScanResultSummary? = null,
    val error: String? = null,
)

data class ScanResultSummary(
    @SerializedName("risk_score") val riskScore: Int? = null,
    val severity: String? = null,
    val verdict: String? = null,
    @SerializedName("malware_family") val malwareFamily: String? = null,
)

data class ScanReportResponse(
    @SerializedName("schema_version") val schemaVersion: String? = null,
    @SerializedName("generated_at") val generatedAt: Long? = null,
    val verdict: String? = null,
    val app: ScanAppInfo? = null,
    val assessment: ScanAssessment? = null,
    @SerializedName("deterministic_score") val deterministicScore: ScanAssessment? = null,
    @SerializedName("static_evidence") val staticEvidence: ScanStaticEvidence? = null,
)

data class ScanAppInfo(
    val name: String? = null,
    val package: String? = null,
    @SerializedName("target_sdk") val targetSdk: Int? = null,
)

data class ScanAssessment(
    @SerializedName("risk_score") val riskScore: Int? = null,
    val severity: String? = null,
    val verdict: String? = null,
    val confidence: String? = null,
    @SerializedName("malware_family") val malwareFamily: String? = null,
    @SerializedName("threat_types") val threatTypes: List<String>? = null,
    @SerializedName("key_findings") val keyFindings: List<String>? = null,
    val recommendations: List<String>? = null,
    val iocs: ScanIocs? = null,
    @SerializedName("score_breakdown") val scoreBreakdown: Map<String, Int>? = null,
)

data class ScanIocs(
    val urls: List<String>? = null,
    val ips: List<String>? = null,
    val apis: List<String>? = null,
)

data class ScanStaticEvidence(
    @SerializedName("dangerous_permissions") val dangerousPermissions: List<String>? = null,
    @SerializedName("suspicious_apis") val suspiciousApis: List<ScanSuspiciousApi>? = null,
    @SerializedName("embedded_urls") val embeddedUrls: List<String>? = null,
    @SerializedName("embedded_ips") val embeddedIps: List<String>? = null,
    val receivers: List<String>? = null,
    val services: List<String>? = null,
    @SerializedName("native_libs") val nativeLibs: List<String>? = null,
    @SerializedName("native_analysis") val nativeAnalysis: ScanNativeAnalysis? = null,
    @SerializedName("tracker_detection") val trackerDetection: ScanTrackerDetection? = null,
    @SerializedName("call_graph") val callGraph: ScanCallGraph? = null,
    @SerializedName("exfiltration_chains") val exfiltrationChains: List<ScanExfilChain>? = null,
    @SerializedName("no_ui_reachable") val noUiReachable: List<String>? = null,
    @SerializedName("yara_matches") val yaraMatches: List<ScanYaraMatch>? = null,
    @SerializedName("signature_verification") val signatureVerification: ScanSignatureVerification? = null,
    @SerializedName("obfuscation_heuristics") val obfuscationHeuristics: Map<String, Any>? = null,
)

data class ScanSuspiciousApi(
    val api: String? = null,
    val category: String? = null,
    @SerializedName("total_callers") val totalCallers: Int? = null,
)

data class ScanNativeAnalysis(
    @SerializedName("suspicious_findings") val suspiciousFindings: List<Map<String, Any>>? = null,
    @SerializedName("high_entropy_sections") val highEntropySections: List<Map<String, Any>>? = null,
    @SerializedName("jni_functions") val jniFunctions: List<String>? = null,
)

data class ScanTrackerDetection(
    val trackers: List<ScanTracker>? = null,
)

data class ScanTracker(
    val name: String? = null,
    val categories: List<String>? = null,
)

data class ScanCallGraph(
    @SerializedName("node_count") val nodeCount: Int? = null,
    @SerializedName("edge_count") val edgeCount: Int? = null,
    @SerializedName("max_depth") val maxDepth: Int? = null,
)

data class ScanExfilChain(
    val source: String? = null,
    val sink: String? = null,
)

data class ScanYaraMatch(
    val rule: String? = null,
    val meta: ScanYaraMeta? = null,
)

data class ScanYaraMeta(
    val description: String? = null,
    val severity: Int? = null,
    val category: String? = null,
)

data class ScanSignatureVerification(
    @SerializedName("is_signed") val isSigned: Boolean? = null,
    val schemes: Map<String, Boolean>? = null,
    val certificates: List<ScanCertificate>? = null,
    val flags: List<String>? = null,
)

data class ScanCertificate(
    val subject: String? = null,
    val issuer: String? = null,
    @SerializedName("sha256_fingerprint") val sha256Fingerprint: String? = null,
    @SerializedName("known_signer_name") val knownSignerName: String? = null,
    val expired: Boolean? = null,
)

data class ScanSummaryResponse(
    val app: ScanAppInfo? = null,
    val assessment: ScanAssessment? = null,
    val verdict: String? = null,
    val summary: ScanSummaryCounts? = null,
)

data class ScanSummaryCounts(
    @SerializedName("yara_match_count") val yaraMatchCount: Int? = null,
    @SerializedName("dangerous_permission_count") val dangerousPermissionCount: Int? = null,
    @SerializedName("suspicious_api_count") val suspiciousApiCount: Int? = null,
    @SerializedName("url_count") val urlCount: Int? = null,
    @SerializedName("ip_count") val ipCount: Int? = null,
    @SerializedName("tracker_count") val trackerCount: Int? = null,
    @SerializedName("native_lib_count") val nativeLibCount: Int? = null,
    @SerializedName("exfiltration_chain_count") val exfiltrationChainCount: Int? = null,
)
