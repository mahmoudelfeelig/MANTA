package com.manta.app.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import com.manta.app.core.settings.ThemeMode

private val LightColors = lightColorScheme(
    primary = Color(0xFF006B5E),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFB6F1E5),
    onPrimaryContainer = Color(0xFF00201B),
    secondary = Color(0xFF52645F),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFD5E7E1),
    onSecondaryContainer = Color(0xFF10201C),
    tertiary = Color(0xFF765A16),
    onTertiary = Color(0xFFFFFFFF),
    tertiaryContainer = Color(0xFFFFE6A6),
    onTertiaryContainer = Color(0xFF251A00),
    background = Color(0xFFF2F5F1),
    onBackground = Color(0xFF14201D),
    surface = Color(0xFFFAFCF8),
    onSurface = Color(0xFF14201D),
    surfaceVariant = Color(0xFFE0E8E3),
    onSurfaceVariant = Color(0xFF43504C),
    outline = Color(0xFF72807B),
    error = Color(0xFFBA1A1A),
    onError = Color(0xFFFFFFFF),
    errorContainer = Color(0xFFFFDAD6),
    onErrorContainer = Color(0xFF410002)
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFF58DEC9),
    onPrimary = Color(0xFF00372F),
    primaryContainer = Color(0xFF124E44),
    onPrimaryContainer = Color(0xFFB6F1E5),
    secondary = Color(0xFFB7CBC4),
    onSecondary = Color(0xFF233631),
    secondaryContainer = Color(0xFF344A44),
    onSecondaryContainer = Color(0xFFD5E7E1),
    tertiary = Color(0xFFEBC66B),
    onTertiary = Color(0xFF3F2E00),
    tertiaryContainer = Color(0xFF594500),
    onTertiaryContainer = Color(0xFFFFE6A6),
    background = Color(0xFF07110F),
    onBackground = Color(0xFFE2E9E5),
    surface = Color(0xFF101B18),
    onSurface = Color(0xFFE2E9E5),
    surfaceVariant = Color(0xFF34443F),
    onSurfaceVariant = Color(0xFFBCCAC5),
    outline = Color(0xFF87958F),
    error = Color(0xFFFFB4AB),
    onError = Color(0xFF690005),
    errorContainer = Color(0xFF93000A),
    onErrorContainer = Color(0xFFFFDAD6)
)

private val MantaTypography = Typography(
    titleLarge = TextStyle(
        fontWeight = FontWeight.Bold,
        fontSize = 22.sp,
        lineHeight = 28.sp
    ),
    titleMedium = TextStyle(
        fontWeight = FontWeight.Bold,
        fontSize = 18.sp,
        lineHeight = 24.sp
    ),
    bodyLarge = TextStyle(
        fontWeight = FontWeight.Normal,
        fontSize = 16.sp,
        lineHeight = 24.sp
    ),
    bodyMedium = TextStyle(
        fontWeight = FontWeight.Normal,
        fontSize = 14.sp,
        lineHeight = 20.sp
    ),
    bodySmall = TextStyle(
        fontWeight = FontWeight.Normal,
        fontSize = 12.sp,
        lineHeight = 16.sp
    ),
    labelLarge = TextStyle(
        fontWeight = FontWeight.Medium,
        fontSize = 13.sp,
        lineHeight = 18.sp
    )
)

@Composable
fun MantaTheme(
    themeMode: ThemeMode = ThemeMode.SYSTEM,
    content: @Composable () -> Unit
) {
    val darkTheme = when (themeMode) {
        ThemeMode.SYSTEM -> isSystemInDarkTheme()
        ThemeMode.LIGHT -> false
        ThemeMode.DARK -> true
    }
    val colors = if (darkTheme) DarkColors else LightColors
    MaterialTheme(
        colorScheme = colors,
        typography = MantaTypography,
        content = content
    )
}
