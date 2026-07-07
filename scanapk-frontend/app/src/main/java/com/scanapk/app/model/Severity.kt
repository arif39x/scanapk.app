package com.scanapk.app.model

enum class Severity(val label: String, val score: Int) {
    SAFE("Safe", 0),
    LOW("Low", 1),
    MEDIUM("Medium", 2),
    HIGH("High", 3),
    CRITICAL("Critical", 4);

    companion object {
        fun fromScore(score: Int): Severity {
            return entries.firstOrNull { it.score == score } ?: SAFE
        }
    }
}
