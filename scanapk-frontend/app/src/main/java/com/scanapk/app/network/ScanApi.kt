package com.scanapk.app.network

import okhttp3.MultipartBody
import retrofit2.http.GET
import retrofit2.http.Multipart
import retrofit2.http.POST
import retrofit2.http.Part
import retrofit2.http.Path

interface ScanApi {

    @Multipart
    @POST("api/v1/scan")
    suspend fun uploadApk(@Part apk: MultipartBody.Part): ScanJobResponse

    @GET("api/v1/scan/{jobId}")
    suspend fun getStatus(@Path("jobId") jobId: String): ScanJobResponse

    @GET("api/v1/scan/{jobId}/report")
    suspend fun getReport(@Path("jobId") jobId: String): ScanReportResponse

    @GET("api/v1/scan/{jobId}/report/summary")
    suspend fun getReportSummary(@Path("jobId") jobId: String): ScanSummaryResponse
}
