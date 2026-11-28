# Themes (GX5): light and dark palettes (Palette.Light.xaml / Palette.Dark.xaml, data only), high contrast built from the Windows
# SystemColors, and the choice: follow Windows (the default), light or dark. Every brush in the window is a DynamicResource, so a new
# palette applies at once. Following Windows reads one per-user setting (AppsUseLightTheme) and SystemParameters.HighContrast every
# two seconds: a read, never a write.

$script:MspkiGuiThemeModes = @('Auto', 'Light', 'Dark')
$script:MspkiGuiPaletteCache = @{}

# Pairs that must stay readable in every palette (foreground, background, minimum ratio): body text 4.5:1 (WCAG 2.x AA), data colours,
# control borders and icons on their own 3:1 (WCAG 1.4.11 non-text contrast).
$script:MspkiGuiContrastPairs = @(
    @('B.Text', 'B.Window', 4.5), @('B.Text', 'B.Nav', 4.5), @('B.Text', 'B.Card', 4.5), @('B.Text', 'B.GridAlt', 4.5), @('B.Text', 'B.Select', 4.5), @('B.Text', 'B.Hover', 4.5),
    @('B.Text', 'B.NeutralBack', 4.5), @('B.Text', 'B.AccentSoft', 4.5),
    @('B.Muted', 'B.Window', 4.5), @('B.Muted', 'B.Nav', 4.5), @('B.Muted', 'B.Card', 4.5), @('B.Muted', 'B.GridAlt', 4.5),
    @('B.GoodFore', 'B.GoodBack', 4.5), @('B.WarnFore', 'B.WarnBack', 4.5), @('B.BadFore', 'B.BadBack', 4.5), @('B.InfoFore', 'B.InfoBack', 4.5),
    @('B.AdminFore', 'B.AdminBack', 4.5), @('B.NeutralFore', 'B.NeutralBack', 4.5),
    @('B.GoodFore', 'B.Card', 4.5), @('B.WarnFore', 'B.Card', 4.5), @('B.BadFore', 'B.Card', 4.5), @('B.InfoFore', 'B.Card', 4.5), @('B.AdminFore', 'B.Card', 4.5),
    @('B.Accent', 'B.Card', 4.5), @('B.AccentDark', 'B.Card', 4.5), @('B.AccentDark', 'B.AccentSoft', 4.5),
    @('B.OnAccent', 'B.Accent', 4.5), @('B.OnAccent', 'B.AccentDark', 4.5),
    @('B.OnHeader', 'B.Header', 4.5), @('B.HeaderSub', 'B.Header', 4.5), @('B.OnHeader', 'B.HeaderHover', 4.5),
    @('B.GoodData', 'B.Card', 3.0), @('B.WarnData', 'B.Card', 3.0), @('B.BadData', 'B.Card', 3.0), @('B.AdminData', 'B.Card', 3.0), @('B.InfoData', 'B.Card', 3.0),
    @('B.NeutralData', 'B.Card', 3.0), @('B.BorderStrong', 'B.Card', 3.0), @('B.Accent', 'B.Window', 3.0),
    @('B.OnData', 'B.GoodData', 3.0), @('B.OnData', 'B.BadData', 3.0), @('B.OnData', 'B.InfoData', 3.0), @('B.OnData', 'B.AdminData', 3.0)
)

function Get-MspkiGuiRelativeLuminance {
    <#
    .SYNOPSIS
    WCAG 2.x relative luminance of a colour given as '#RRGGBB' or '#AARRGGBB' (alpha ignored).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Color)
    $h = $Color.TrimStart('#')
    if ($h.Length -eq 8) { $h = $h.Substring(2) }
    $c = foreach ($i in 0, 2, 4) {
        $v = [Convert]::ToInt32($h.Substring($i, 2), 16) / 255.0
        if ($v -le 0.03928) { $v / 12.92 } else { [Math]::Pow(($v + 0.055) / 1.055, 2.4) }
    }
    return (0.2126 * $c[0] + 0.7152 * $c[1] + 0.0722 * $c[2])
}

function Get-MspkiGuiContrastRatio {
    <#
    .SYNOPSIS
    WCAG contrast ratio (1 to 21) between two colours.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Foreground, [Parameter(Mandatory = $true)][string]$Background)
    $a = Get-MspkiGuiRelativeLuminance -Color $Foreground
    $b = Get-MspkiGuiRelativeLuminance -Color $Background
    return (([Math]::Max($a, $b) + 0.05) / ([Math]::Min($a, $b) + 0.05))
}

function Read-MspkiGuiPaletteColor {
    <#
    .SYNOPSIS
    The colours of a palette file as a table key -> '#RRGGBB' (read as XML: no WPF needed). Used by the contrast test.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)
    $x = New-Object System.Xml.XmlDocument
    $x.Load($Path)
    $ns = New-Object System.Xml.XmlNamespaceManager($x.NameTable)
    $ns.AddNamespace('p', 'http://schemas.microsoft.com/winfx/2006/xaml/presentation')
    $ns.AddNamespace('x', 'http://schemas.microsoft.com/winfx/2006/xaml')
    $t = @{}
    foreach ($n in $x.SelectNodes('//p:SolidColorBrush', $ns)) { $t[$n.GetAttribute('Key', 'http://schemas.microsoft.com/winfx/2006/xaml')] = $n.GetAttribute('Color') }
    return $t
}

function Test-MspkiGuiWindowsDarkMode {
    <#
    .SYNOPSIS
    True when Windows is set to dark mode for apps (HKCU ...\Themes\Personalize, AppsUseLightTheme = 0). Read only; $false when unknown.
    #>
    [CmdletBinding()]
    param()
    try {
        $v = [Microsoft.Win32.Registry]::GetValue('HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize', 'AppsUseLightTheme', $null)
        return ($null -ne $v -and [int]$v -eq 0)
    }
    catch { return $false }
}

function Resolve-MspkiGuiTheme {
    <#
    .SYNOPSIS
    The palette to show: HighContrast whenever Windows high contrast is on, otherwise the user's choice (Light, Dark), or Windows' own
    setting for Auto.
    #>
    [CmdletBinding()]
    param([ValidateSet('Auto', 'Light', 'Dark')][string]$Mode = 'Auto', [bool]$WindowsDark = $false, [bool]$HighContrast = $false)
    if ($HighContrast) { return 'HighContrast' }
    if ($Mode -eq 'Light') { return 'Light' }
    if ($Mode -eq 'Dark') { return 'Dark' }
    if ($WindowsDark) { return 'Dark' }
    return 'Light'
}

function New-MspkiGuiHighContrastPalette {
    <#
    .SYNOPSIS
    A palette with the same keys whose brushes are the Windows high-contrast SystemColors (window, text, highlight, grey text, caption).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string[]]$Keys)
    $sc = [System.Windows.SystemColors]
    $d = New-Object System.Windows.ResourceDictionary
    foreach ($k in $Keys) {
        $b = $sc::WindowTextBrush
        switch -Regex ($k) {
            '^B\.(Window|Nav|Card|GridHead|GridAlt|Hover|SubtleHover|DisabledBack|AccentSoft|NeutralBack|FieldHover|NavSelect|Badge|FocusRingInner|(Good|Warn|Bad|Info|Admin)Back)$' { $b = $sc::WindowBrush; break }
            '^B\.(Accent|AccentDark|AccentPressed|Select|Pressed|(Good|Warn|Bad|Info|Admin)Data|CloseHover|CloseHoverPressed|HeaderHover|HeaderPressed)$' { $b = $sc::HighlightBrush; break }
            '^B\.(OnAccent|OnData)$' { $b = $sc::HighlightTextBrush; break }
            '^B\.(Disabled|NeutralData)$' { $b = $sc::GrayTextBrush; break }
            '^B\.Header$' { $b = $sc::ActiveCaptionBrush; break }
            '^B\.(OnHeader|HeaderSub|HeaderLine)$' { $b = $sc::ActiveCaptionTextBrush; break }
        }
        $d[$k] = $b
    }
    return $d
}

function Import-MspkiGuiPalette {
    <#
    .SYNOPSIS
    The ResourceDictionary of a theme (Light, Dark or HighContrast). The two palette files are read once and kept.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][ValidateSet('Light', 'Dark', 'HighContrast')][string]$Theme)
    if ($Theme -ne 'HighContrast' -and $script:MspkiGuiPaletteCache.ContainsKey($Theme)) { return $script:MspkiGuiPaletteCache[$Theme] }
    $light = $null
    if ($script:MspkiGuiPaletteCache.ContainsKey('Light')) { $light = $script:MspkiGuiPaletteCache['Light'] }
    if ($Theme -eq 'HighContrast') {
        if ($null -eq $light) { $light = Import-MspkiGuiPalette -Theme Light }
        return (New-MspkiGuiHighContrastPalette -Keys @($light.Keys | ForEach-Object { [string]$_ }))
    }
    $path = Join-Path $PSScriptRoot ('Palette.{0}.xaml' -f $Theme)
    $stream = [System.IO.File]::OpenRead($path)
    try { $d = [System.Windows.Markup.XamlReader]::Load($stream) }
    finally { $stream.Dispose() }
    $script:MspkiGuiPaletteCache[$Theme] = $d
    return $d
}

function Set-MspkiGuiTheme {
    <#
    .SYNOPSIS
    Applies a theme choice (Auto follows Windows) to the open window: swaps the palette, redraws what the code draws (score ring, area
    bars, map) and updates the theme button. -Force applies even when the palette has not changed.
    #>
    [CmdletBinding()]
    param([ValidateSet('Auto', 'Light', 'Dark')][string]$Mode = 'Auto', [switch]$Force)
    $g = $script:MspkiGui
    if ($null -eq $g -or $null -eq $g.Window) { return }
    $g.ThemeMode = $Mode
    $eff = Resolve-MspkiGuiTheme -Mode $Mode -WindowsDark (Test-MspkiGuiWindowsDarkMode) -HighContrast ([System.Windows.SystemParameters]::HighContrast)
    $changed = ($eff -ne [string]$g.ThemeEffective)
    if ($changed -or $Force) {
        $md = $g.Window.Resources.MergedDictionaries
        $md[0] = (Import-MspkiGuiPalette -Theme $eff)
        $g.ThemeEffective = $eff
        if ($null -ne $g.Score) {
            try { Update-MspkiGuiScoreView -Score $g.Score; Update-MspkiGuiActionView -Actions $g.Actions; Invoke-MspkiGuiMapDraw -Force } catch { $null = $_ }
        }
    }
    $ui = $g.Ui
    if ($ui.ContainsKey('BtnTheme')) {
        $glyph = @{ Auto = 0xE7F4; Light = 0xE706; Dark = 0xE708 }[$Mode]
        $words = @{ Auto = 'follow Windows'; Light = 'light'; Dark = 'dark' }[$Mode]
        $next = @{ Auto = 'light'; Light = 'dark'; Dark = 'follow Windows' }[$Mode]
        $now = $words; if ($eff -eq 'HighContrast') { $now = $words + ' (Windows high contrast is on, so its colours are used)' }
        $ui.BtnTheme.Content = [string][char]$glyph
        $ui.BtnTheme.ToolTip = ('Theme: {0}. Click for {1}.' -f $now, $next)
        [System.Windows.Automation.AutomationProperties]::SetName($ui.BtnTheme, ('Theme: {0} (click for {1})' -f $words, $next))
    }
    # Reduced motion also stills the popup fade (the window's own animations ask Test-MspkiGuiReducedMotion each time).
    if ($ui.ContainsKey('PopScore')) { $ui.PopScore.PopupAnimation = $(if (Test-MspkiGuiReducedMotion) { 'None' } else { 'Fade' }) }
}

function Switch-MspkiGuiTheme {
    <#
    .SYNOPSIS
    The theme button: follow Windows -> light -> dark -> follow Windows.
    #>
    [CmdletBinding()]
    param()
    $g = $script:MspkiGui
    $cur = [string]$g.ThemeMode; if (-not $cur) { $cur = 'Auto' }
    $next = @{ Auto = 'Light'; Light = 'Dark'; Dark = 'Auto' }[$cur]
    Set-MspkiGuiTheme -Mode $next
    $eff = [string]$g.ThemeEffective
    [void](Show-MspkiGuiToast -Text ('Theme: {0}.' -f @{ Auto = 'follow Windows'; Light = 'light'; Dark = 'dark' }[$next]) -Seconds 3 -Tone Info)
    $null = $eff
}

function Start-MspkiGuiThemeWatch {
    <#
    .SYNOPSIS
    Follows Windows while the window is open: every two seconds, a change of dark mode (when the choice is Auto) or of high contrast
    applies the matching palette. Stopped when the window closes.
    #>
    [CmdletBinding()]
    param()
    $g = $script:MspkiGui
    $t = New-Object System.Windows.Threading.DispatcherTimer
    $t.Interval = [TimeSpan]::FromSeconds(2)
    $t.Add_Tick({
        $s = $script:MspkiGui
        try {
            $eff = Resolve-MspkiGuiTheme -Mode ([string]$s.ThemeMode) -WindowsDark (Test-MspkiGuiWindowsDarkMode) -HighContrast ([System.Windows.SystemParameters]::HighContrast)
            if ($eff -ne [string]$s.ThemeEffective) { Set-MspkiGuiTheme -Mode ([string]$s.ThemeMode) }
        }
        catch { $null = $_ }
    })
    $t.Start()
    $g.ThemeTimer = $t
}
