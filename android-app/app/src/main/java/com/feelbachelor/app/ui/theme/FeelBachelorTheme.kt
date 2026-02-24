package com.feelbachelor.app.ui.theme

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

private val LightColors = lightColorScheme(
    primary = Color(0xFF006B65),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFF8BF8EC),
    onPrimaryContainer = Color(0xFF00201D),
    secondary = Color(0xFF4A635F),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFCDE8E2),
    onSecondaryContainer = Color(0xFF05201D),
    tertiary = Color(0xFF755A2F),
    onTertiary = Color(0xFFFFFFFF),
    tertiaryContainer = Color(0xFFFFDDAE),
    onTertiaryContainer = Color(0xFF281800),
    background = Color(0xFFF4FBF9),
    onBackground = Color(0xFF161D1B),
    surface = Color(0xFFFBFDFB),
    onSurface = Color(0xFF161D1B),
    surfaceVariant = Color(0xFFDCE5E2),
    onSurfaceVariant = Color(0xFF3F4946),
    outline = Color(0xFF6F7976),
    error = Color(0xFFBA1A1A),
    onError = Color(0xFFFFFFFF),
    errorContainer = Color(0xFFFFDAD6),
    onErrorContainer = Color(0xFF410002)
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFF6EDBD0),
    onPrimary = Color(0xFF003733),
    primaryContainer = Color(0xFF005049),
    onPrimaryContainer = Color(0xFF8BF8EC),
    secondary = Color(0xFFB2CCC6),
    onSecondary = Color(0xFF1E3531),
    secondaryContainer = Color(0xFF344C48),
    onSecondaryContainer = Color(0xFFCDE8E2),
    tertiary = Color(0xFFE4C18D),
    onTertiary = Color(0xFF422C06),
    tertiaryContainer = Color(0xFF5B421B),
    onTertiaryContainer = Color(0xFFFFDDAE),
    background = Color(0xFF101513),
    onBackground = Color(0xFFDEE4E1),
    surface = Color(0xFF171C1B),
    onSurface = Color(0xFFDEE4E1),
    surfaceVariant = Color(0xFF3F4946),
    onSurfaceVariant = Color(0xFFBFC9C6),
    outline = Color(0xFF89938F),
    error = Color(0xFFFFB4AB),
    onError = Color(0xFF690005),
    errorContainer = Color(0xFF93000A),
    onErrorContainer = Color(0xFFFFDAD6)
)

private val FeelTypography = Typography(
    titleLarge = TextStyle(
        fontWeight = FontWeight.SemiBold,
        fontSize = 22.sp,
        lineHeight = 28.sp
    ),
    titleMedium = TextStyle(
        fontWeight = FontWeight.SemiBold,
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
fun FeelBachelorTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    val colors = if (darkTheme) DarkColors else LightColors
    MaterialTheme(
        colorScheme = colors,
        typography = FeelTypography,
        content = content
    )
}
