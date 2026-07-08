package com.scanapk.app.model

enum class Severity(val label: String, val score: Int) {
    SAFE("Safe", 0),
    LOW("Low", 1),
    MEDIUM("Medium", 2),
    HIGH("High", 3),
    CRITICAL("Critical", 4);

    companion object {
        private val scoreMap = entries.associateBy { it.score }
        fun fromScore(score: Int): Severity = scoreMap[score] ?: SAFE
    }
}
