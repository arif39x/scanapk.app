package com.scanapk.app.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.scanapk.app.model.Severity
import com.scanapk.app.ui.theme.SeverityCritical
import com.scanapk.app.ui.theme.SeverityCriticalBg
import com.scanapk.app.ui.theme.SeverityHigh
import com.scanapk.app.ui.theme.SeverityHighBg
import com.scanapk.app.ui.theme.SeverityLow
import com.scanapk.app.ui.theme.SeverityLowBg
import com.scanapk.app.ui.theme.SeverityMedium
import com.scanapk.app.ui.theme.SeverityMediumBg
import com.scanapk.app.ui.theme.SeveritySafe
import com.scanapk.app.ui.theme.SeveritySafeBg

@Composable
fun SeverityChip(
    severity: Severity,
    modifier: Modifier = Modifier,
) {
    val (bgColor, textColor) = when (severity) {
        Severity.SAFE -> SeveritySafeBg to SeveritySafe
        Severity.LOW -> SeverityLowBg to SeverityLow
        Severity.MEDIUM -> SeverityMediumBg to SeverityMedium
        Severity.HIGH -> SeverityHighBg to SeverityHigh
        Severity.CRITICAL -> SeverityCriticalBg to SeverityCritical
    }

    Text(
        text = severity.label,
        color = textColor,
        fontSize = 12.sp,
        fontWeight = FontWeight.Medium,
        modifier = modifier
            .clip(RoundedCornerShape(4.dp))
            .background(bgColor)
            .padding(horizontal = 8.dp, vertical = 4.dp),
    )
}
