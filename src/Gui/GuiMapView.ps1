# Mission-control Overview, WPF side: the score ring, the area bars, the "What to do next" rows and the discovery map canvas, plus
# the one Storyboard that builds them on screen. All motion is WPF animation (no PowerShell work per frame). With reduced motion
# (Windows "Show animations" off, high contrast, or software rendering) nothing animates and the final state is shown at once.
# The data comes from GuiMission.ps1 (pure functions); nothing here decides what is healthy.

# Per tone: background, line, foreground (text and icons) and the data colour (ring and bars).
$script:MspkiGuiToneKeys = @{
    Good = @('B.GoodBack', 'B.GoodLine', 'B.GoodFore', 'B.GoodData'); Warn = @('B.WarnBack', 'B.WarnLine', 'B.WarnFore', 'B.WarnData')
    Bad = @('B.BadBack', 'B.BadLine', 'B.BadFore', 'B.BadData'); Info = @('B.InfoBack', 'B.InfoLine', 'B.InfoFore', 'B.InfoData')
    Admin = @('B.AdminBack', 'B.AdminLine', 'B.AdminFore', 'B.AdminData'); Neutral = @('B.NeutralBack', 'B.NeutralLine', 'B.NeutralFore', 'B.NeutralData')
}
$script:MspkiGuiMapHeaderHeight = 28.0

function Get-MspkiGuiColorOf {
    # The colour of a theme brush (a new, unfrozen brush can then be animated).
    param([string]$Key)
    return $script:MspkiGui.Window.FindResource($Key).Color
}

function New-MspkiGuiBrushOf {
    param([string]$Key)
    return (New-Object System.Windows.Media.SolidColorBrush((Get-MspkiGuiColorOf -Key $Key)))
}

function Test-MspkiGuiReducedMotion {
    <#
    .SYNOPSIS
    True when the window should not animate: Windows "Show animations" is off, high contrast is on, or WPF renders in software.
    Developer snapshots force motion so that mid-animation frames can be captured.
    #>
    [CmdletBinding()]
    param()
    if ($null -ne $script:MspkiGui -and $script:MspkiGui.ContainsKey('ForceReducedMotion') -and $script:MspkiGui.ForceReducedMotion) { return $true }
    if ($null -ne $script:MspkiGui -and $script:MspkiGui.ContainsKey('ForceMotion') -and $script:MspkiGui.ForceMotion) { return $false }
    if (-not [System.Windows.SystemParameters]::ClientAreaAnimation) { return $true }
    if ([System.Windows.SystemParameters]::HighContrast) { return $true }
    if (([System.Windows.Media.RenderCapability]::Tier -shr 16) -eq 0) { return $true }
    return $false
}

function Add-MspkiGuiKeyAnimation {
    <#
    .SYNOPSIS
    Adds one key-frame animation to the storyboard: the property holds From until -StartMs, then eases to To over -DurationMs.
    The property's own (base) value must be the final state, so the window is complete when no animation runs.
    #>
    param($Storyboard, $Target, $Path, [double]$StartMs, [double]$DurationMs, $From, $To, [switch]$Color, $Ease = $null)
    if ($Color) {
        $a = New-Object System.Windows.Media.Animation.ColorAnimationUsingKeyFrames
        [void]$a.KeyFrames.Add((New-Object System.Windows.Media.Animation.DiscreteColorKeyFrame($From, [System.Windows.Media.Animation.KeyTime]::FromTimeSpan([TimeSpan]::Zero))))
        if ($StartMs -gt 0) { [void]$a.KeyFrames.Add((New-Object System.Windows.Media.Animation.DiscreteColorKeyFrame($From, [System.Windows.Media.Animation.KeyTime]::FromTimeSpan([TimeSpan]::FromMilliseconds($StartMs))))) }
        [void]$a.KeyFrames.Add((New-Object System.Windows.Media.Animation.LinearColorKeyFrame($To, [System.Windows.Media.Animation.KeyTime]::FromTimeSpan([TimeSpan]::FromMilliseconds($StartMs + $DurationMs)))))
    }
    else {
        $a = New-Object System.Windows.Media.Animation.DoubleAnimationUsingKeyFrames
        [void]$a.KeyFrames.Add((New-Object System.Windows.Media.Animation.DiscreteDoubleKeyFrame([double]$From, [System.Windows.Media.Animation.KeyTime]::FromTimeSpan([TimeSpan]::Zero))))
        if ($StartMs -gt 0) { [void]$a.KeyFrames.Add((New-Object System.Windows.Media.Animation.DiscreteDoubleKeyFrame([double]$From, [System.Windows.Media.Animation.KeyTime]::FromTimeSpan([TimeSpan]::FromMilliseconds($StartMs))))) }
        $k = New-Object System.Windows.Media.Animation.EasingDoubleKeyFrame([double]$To, [System.Windows.Media.Animation.KeyTime]::FromTimeSpan([TimeSpan]::FromMilliseconds($StartMs + $DurationMs)))
        if ($null -ne $Ease) { $k.EasingFunction = $Ease }
        [void]$a.KeyFrames.Add($k)
    }
    $a.FillBehavior = [System.Windows.Media.Animation.FillBehavior]::HoldEnd
    [System.Windows.Media.Animation.Storyboard]::SetTarget($a, $Target)
    [System.Windows.Media.Animation.Storyboard]::SetTargetProperty($a, $Path)
    $Storyboard.Children.Add($a)
}

function New-MspkiGuiEase {
    param([ValidateSet('Out', 'InOut')][string]$Mode = 'Out')
    $e = New-Object System.Windows.Media.Animation.CubicEase
    $e.EasingMode = $(if ($Mode -eq 'Out') { [System.Windows.Media.Animation.EasingMode]::EaseOut } else { [System.Windows.Media.Animation.EasingMode]::EaseInOut })
    return $e
}

function Update-MspkiGuiScoreView {
    <#
    .SYNOPSIS
    Shows the score ring, the band, the partial note and the area bars for a score from Get-MspkiGuiHealthScore.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Score)
    $g = $script:MspkiGui
    $ui = $g.Ui
    $ring = $ui.ScoreArc
    $thick = $ring.StrokeThickness
    $circ = [math]::PI * ($ui.ScoreRing.Width - $thick) / $thick
    $frac = $(if ($Score.HasScore) { [double]$Score.Overall / 100.0 } else { 0.0 })
    $len = [math]::Max(0.0001, $frac * $circ)
    $dash = New-Object System.Windows.Media.DoubleCollection
    [void]$dash.Add($len); [void]$dash.Add($circ + 2)
    $ring.StrokeDashArray = $dash
    $ring.StrokeDashOffset = 0
    $keys = $script:MspkiGuiToneKeys[[string]$Score.Tone]
    $ring.Stroke = $g.Window.FindResource($keys[3])
    $ring.Visibility = $(if ($Score.HasScore) { 'Visible' } else { 'Hidden' })
    $ui.TxtScore.Text = $Score.OverallText
    $ui.TxtScoreOf.Text = $(if ($Score.HasScore) { 'out of 100' } else { 'no score' })
    $band = $(if ($Score.HasScore) { New-MspkiGuiPill -Text $Score.Band -Tone $Score.Tone -Code ([int][char]$Score.Glyph) } else { New-MspkiGuiPill -Text 'Not scored' -Tone Neutral -Code 0xE738 })
    $ui.ScoreBand.Content = $band
    $ui.ScoreRing.ToolTip = $(if ($Score.HasScore) { $Score.HowText } else { $Score.Reason })
    $ui.BtnScoreHow.ToolTip = $Score.HowText
    # "Partial score" pill under the band; the full sentence is its tooltip. Without a score the reason replaces the band's tooltip.
    $ui.ScorePartial.ToolTip = $Score.PartialText
    $ui.ScorePartial.Visibility = $(if ($Score.Partial -and $Score.HasScore) { 'Visible' } else { 'Collapsed' })
    [System.Windows.Automation.AutomationProperties]::SetName($ui.ScorePartial, [string]$Score.PartialText)
    $ui.ScoreBand.ToolTip = $(if ($Score.HasScore) { $Score.HowText } else { $Score.Reason })
    # D-24: when the cap holds the overall down, say which area does it, in the first screen.
    $ui.TxtScoreReason.Text = $(if ($Score.HasScore) { [string]$Score.HeldText } else { [string]$Score.Reason })
    $ui.TxtScoreReason.Visibility = $(if (-not $Score.HasScore -or $Score.HeldText) { 'Visible' } else { 'Collapsed' })
    $ui.TxtScoreReason.ToolTip = $(if ($Score.HasScore -and $Score.HeldTip) { [string]$Score.HeldTip } else { $null })

    $ui.AreaPanel.Children.Clear()
    $g.AreaFills = New-Object System.Collections.ArrayList
    $rowStyle = $g.Window.FindResource('RowButton')
    foreach ($a in @($Score.Areas)) {
        $b = New-Object System.Windows.Controls.Button
        $b.Style = $rowStyle
        $b.Padding = New-Object System.Windows.Thickness(8, 7, 8, 7)
        $b.Tag = [string]$a.Tag
        $b.ToolTip = $(if ($a.Count -gt 0) { '{0}: {1}. Select to see these findings.' -f $a.Name, $a.Detail } else { '{0}: no finding in this run belongs to this area.' -f $a.Name })
        [System.Windows.Automation.AutomationProperties]::SetName($b, [string]$a.AccessibleName)
        $grid = New-Object System.Windows.Controls.Grid
        foreach ($w in @(20, 128, -1, 68)) {
            $cd = New-Object System.Windows.Controls.ColumnDefinition
            $cd.Width = $(if ($w -lt 0) { New-Object System.Windows.GridLength(1, [System.Windows.GridUnitType]::Star) } else { New-Object System.Windows.GridLength($w) })
            $grid.ColumnDefinitions.Add($cd)
        }
        $k = $script:MspkiGuiToneKeys[[string]$a.Tone]
        $gl = New-Object System.Windows.Controls.TextBlock
        $gl.Style = $g.Window.FindResource('Glyph'); $gl.Text = [string]$a.Glyph; $gl.FontSize = 12; $gl.Foreground = $g.Window.FindResource($k[2]); $gl.VerticalAlignment = 'Center'
        $nm = New-Object System.Windows.Controls.TextBlock
        $nm.Text = [string]$a.Name; $nm.TextTrimming = 'CharacterEllipsis'; $nm.VerticalAlignment = 'Center'; $nm.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'B.Text')
        [System.Windows.Controls.Grid]::SetColumn($nm, 1)
        $track = New-Object System.Windows.Controls.Grid
        $track.Height = 6; $track.VerticalAlignment = 'Center'; $track.Margin = New-Object System.Windows.Thickness(4, 0, 12, 0)
        $bg = New-Object System.Windows.Controls.Border
        $bg.CornerRadius = New-Object System.Windows.CornerRadius(3); $bg.Background = $g.Window.FindResource('B.Divider')
        [void]$track.Children.Add($bg)
        [System.Windows.Controls.Grid]::SetColumn($track, 2)
        if ($null -ne $a.Score) {
            $inner = New-Object System.Windows.Controls.Grid
            $c1 = New-Object System.Windows.Controls.ColumnDefinition; $c1.Width = New-Object System.Windows.GridLength([math]::Max(0.5, [double]$a.Score), [System.Windows.GridUnitType]::Star)
            $c2 = New-Object System.Windows.Controls.ColumnDefinition; $c2.Width = New-Object System.Windows.GridLength([math]::Max(0.0, 100.0 - [double]$a.Score), [System.Windows.GridUnitType]::Star)
            $inner.ColumnDefinitions.Add($c1); $inner.ColumnDefinitions.Add($c2)
            $fill = New-Object System.Windows.Controls.Border
            $fill.CornerRadius = New-Object System.Windows.CornerRadius(3); $fill.Background = $g.Window.FindResource($k[3])
            $fill.RenderTransformOrigin = New-Object System.Windows.Point(0, 0.5)
            $fill.RenderTransform = New-Object System.Windows.Media.ScaleTransform(1, 1)
            [void]$inner.Children.Add($fill)
            [void]$track.Children.Add($inner)
        }
        $sc = New-Object System.Windows.Controls.TextBlock
        $sc.Text = [string]$a.ScoreText; $sc.FontWeight = 'SemiBold'; $sc.HorizontalAlignment = 'Right'; $sc.VerticalAlignment = 'Center'
        # D-25: an area without findings says "not scored" in words, quietly, with the reason in the row tooltip.
        if ($null -eq $a.Score) { $sc.Text = 'not scored'; $sc.FontWeight = 'Normal'; $sc.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'B.Muted') }
        # The bar and its number appear together in the build animation.
        [void]$g.AreaFills.Add([pscustomobject]@{ Fill = $(if ($null -ne $a.Score) { $fill } else { $null }); Text = $sc })
        [System.Windows.Controls.Grid]::SetColumn($sc, 3)
        foreach ($c in @($gl, $nm, $track, $sc)) { [void]$grid.Children.Add($c) }
        $b.Content = $grid
        [void]$ui.AreaPanel.Children.Add($b)
    }
}

function Update-MspkiGuiActionView {
    <#
    .SYNOPSIS
    Shows the first "What to do next" actions in the hero and the link to all of them.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Actions, [int]$Show = 5, [switch]$Expanded)
    $ui = $script:MspkiGui.Ui
    $items = @($Actions.Items | Select-Object -First $(if ($Expanded) { [int]$Actions.Total } else { $Show }))
    $ui.ActionList.ItemsSource = $items
    $ui.PanelNoAction.Visibility = $(if ($Actions.Total -eq 0) { 'Visible' } else { 'Collapsed' })
    $ui.BtnAllActions.Visibility = $(if ($Actions.Total -gt $Show) { 'Visible' } else { 'Collapsed' })
    $ui.BtnAllActions.Content = $(if ($Expanded) { 'Show fewer' } else { 'All {0}' -f (Format-MspkiGuiCount -Count $Actions.Total -Singular 'action') })
    [System.Windows.Automation.AutomationProperties]::SetName($ui.BtnAllActions, $(if ($Expanded) { 'Show only the five most urgent actions' } else { 'Show all {0}' -f (Format-MspkiGuiCount -Count $Actions.Total -Singular 'action') }))
}

function Switch-MspkiGuiActionList {
    <#
    .SYNOPSIS
    "All N actions" / "Show fewer": lists every action under "What to do next" instead of the five most urgent (and back).
    #>
    [CmdletBinding()]
    param()
    $g = $script:MspkiGui
    if ($null -eq $g.Actions) { return }
    $g.ActionsExpanded = -not [bool]$g.ActionsExpanded
    Update-MspkiGuiActionView -Actions $g.Actions -Expanded:([bool]$g.ActionsExpanded)
}

function Measure-MspkiGuiTextWidth {
    param($TextBlock)
    $TextBlock.Measure((New-Object System.Windows.Size([double]::PositiveInfinity, [double]::PositiveInfinity)))
    return $TextBlock.DesiredSize.Width
}

function New-MspkiGuiMapNodeVisual {
    <#
    .SYNOPSIS
    Adds one map node to a canvas: the probe pulse (behind everything), the circle with its icon (or the count of a group), the status
    badge (icon, never colour alone, outside the icon), and the label in an opaque box so that links and pulses pass behind the text.
    Returns the drawn record. The label box and the circle carry the node's id in Tag ("node:<id>") and its accessible name.
    #>
    param([Parameter(Mandatory = $true)]$Node, [Parameter(Mandatory = $true)]$Canvas, [double]$Top, [double]$Gap = 38)
    $w = $script:MspkiGui.Window
    $n = $Node
    $x = [double]$n.X; $y = [double]$n.Y + $Top
    $keys = $script:MspkiGuiToneKeys[[string]$n.Tone]
    if ($null -eq $keys) { $keys = $script:MspkiGuiToneKeys['Neutral'] }
    $word = $script:MspkiGuiToneWord[[string]$n.Tone]
    $tag = 'node:' + [string]$n.Id
    $tip = '{0}{1}{2}{1}Status: {3}{4}' -f [string]$n.FullName, [Environment]::NewLine, [string]$n.Sub, $word, $(if ($n.Kind -eq 'Cluster') { '' } elseif ($n.Kind -eq 'Unknown') { [Environment]::NewLine + [string]$n.Explain } else { '. Select to open it.' })
    if ($n.Kind -eq 'Cluster') { $tip = '{0}{1}Worst status: {2}. Select to expand the group.' -f [string]$n.FullName, [Environment]::NewLine, $word }
    if ($null -ne $n.PSObject.Properties['WhereText'] -and $n.WhereText) { $tip += [Environment]::NewLine + [Environment]::NewLine + [string]$n.WhereText }
    $acc = '{0}, {1}, {2}' -f [string]$n.Label, [string]$n.Sub, $word

    # Probe pulse: at most the row spacing across, so it never reaches a neighbouring label (owner review item 3).
    $pulse = $null
    if ($n.Kind -in @('Endpoint', 'Host', 'Cluster')) {
        $pulse = New-Object System.Windows.Shapes.Ellipse
        $pulse.Width = 26; $pulse.Height = 26; $pulse.Stroke = $w.FindResource('B.Accent'); $pulse.StrokeThickness = 2
        $pulse.Opacity = 0; $pulse.IsHitTestVisible = $false
        $pulse.RenderTransformOrigin = New-Object System.Windows.Point(0.5, 0.5)
        $pulse.RenderTransform = New-Object System.Windows.Media.ScaleTransform(1, 1)
        $pulse.Tag = [math]::Max(1.15, [math]::Min(2.3, ($Gap - 4) / 26.0))
        [System.Windows.Controls.Canvas]::SetLeft($pulse, $x); [System.Windows.Controls.Canvas]::SetTop($pulse, $y - 13)
        [System.Windows.Controls.Panel]::SetZIndex($pulse, 1)
        [void]$Canvas.Children.Add($pulse)
    }
    $body = New-Object System.Windows.Controls.Grid
    $body.Width = 26; $body.Height = 26
    $body.RenderTransformOrigin = New-Object System.Windows.Point(0.5, 0.5)
    $body.RenderTransform = New-Object System.Windows.Media.ScaleTransform(1, 1)
    $body.Tag = $tag; $body.Cursor = [System.Windows.Input.Cursors]::Hand; $body.ToolTip = $tip; $body.Background = [System.Windows.Media.Brushes]::Transparent
    [System.Windows.Automation.AutomationProperties]::SetName($body, $acc)
    $circle = New-Object System.Windows.Shapes.Ellipse
    $circle.Fill = New-MspkiGuiBrushOf -Key $keys[0]
    $circle.Stroke = New-MspkiGuiBrushOf -Key $keys[1]
    $circle.StrokeThickness = 1.5
    if ($n.Kind -eq 'Unknown') { $circle.StrokeDashArray = [System.Windows.Media.DoubleCollection]::Parse('2.0 2.0') }
    $icon = New-Object System.Windows.Controls.TextBlock
    if ($n.Kind -eq 'Cluster') { $icon.Text = [string]$n.Count; $icon.FontSize = $(if ($n.Count -ge 100) { 9 } else { 11 }); $icon.FontWeight = 'Bold' }
    else { $icon.Style = $w.FindResource('Glyph'); $icon.Text = [string]$n.Glyph; $icon.FontSize = 12 }
    $icon.Foreground = New-MspkiGuiBrushOf -Key $keys[2]
    $icon.HorizontalAlignment = 'Center'; $icon.VerticalAlignment = 'Center'
    [void]$body.Children.Add($circle); [void]$body.Children.Add($icon)
    [System.Windows.Controls.Canvas]::SetLeft($body, $x); [System.Windows.Controls.Canvas]::SetTop($body, $y - 13)
    [System.Windows.Controls.Panel]::SetZIndex($body, 3)
    [void]$Canvas.Children.Add($body)

    # Status badge: 18 px, a 10 px glyph, up and to the right of the circle so it never covers the icon (owner review item 4).
    $mark = $null
    $badge = @{ Bad = 0xE711; Warn = 0xE7BA; Admin = 0xE72E }
    if ($badge.ContainsKey([string]$n.Tone)) {
        $mark = New-Object System.Windows.Controls.Border
        $mark.Width = 18; $mark.Height = 18; $mark.CornerRadius = New-Object System.Windows.CornerRadius(9)
        $mark.Background = $w.FindResource($keys[2]); $mark.BorderBrush = $w.FindResource('B.Card'); $mark.BorderThickness = New-Object System.Windows.Thickness(2)
        $mark.IsHitTestVisible = $false
        $mg = New-Object System.Windows.Controls.TextBlock
        $mg.Style = $w.FindResource('Glyph'); $mg.Text = [string][char]$badge[[string]$n.Tone]; $mg.FontSize = 9; $mg.FontWeight = 'Bold'; $mg.Foreground = $w.FindResource('B.OnData')
        $mg.HorizontalAlignment = 'Center'; $mg.VerticalAlignment = 'Center'
        $mark.Child = $mg
        [System.Windows.Controls.Canvas]::SetLeft($mark, $x + 18); [System.Windows.Controls.Canvas]::SetTop($mark, $y - 23)
        [System.Windows.Controls.Panel]::SetZIndex($mark, 4)
        [void]$Canvas.Children.Add($mark)
    }
    # Label in an opaque box as wide as its text (hover and selection tint it).
    $sp = New-Object System.Windows.Controls.StackPanel
    $t1 = New-Object System.Windows.Controls.TextBlock
    $t1.Text = [string]$n.Label; $t1.FontWeight = 'SemiBold'; $t1.FontSize = 12; $t1.TextTrimming = 'CharacterEllipsis'; $t1.TextWrapping = 'NoWrap'; $t1.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'B.Text')
    $t2 = New-Object System.Windows.Controls.TextBlock
    $t2.Text = $(if ($n.Context) { [string]$n.Sub + ' ' + [char]0x00B7 + ' shown for context' } else { [string]$n.Sub }); $t2.Style = $w.FindResource('Small'); $t2.TextTrimming = 'CharacterEllipsis'; $t2.TextWrapping = 'NoWrap'
    [void]$sp.Children.Add($t1); [void]$sp.Children.Add($t2)
    $max = [math]::Max(40.0, [double]$n.LabelWidth)
    $used = [math]::Min($max, [math]::Max((Measure-MspkiGuiTextWidth -TextBlock $t1), (Measure-MspkiGuiTextWidth -TextBlock $t2)))
    $sp.Width = $used + 1
    $lab = New-Object System.Windows.Controls.Border
    $lab.Child = $sp; $lab.Padding = New-Object System.Windows.Thickness(4, 1, 4, 1); $lab.CornerRadius = New-Object System.Windows.CornerRadius(4)
    $lab.SetResourceReference([System.Windows.Controls.Border]::BackgroundProperty, 'B.Card')
    $lab.Tag = $tag; $lab.Cursor = [System.Windows.Input.Cursors]::Hand; $lab.ToolTip = $tip
    [System.Windows.Automation.AutomationProperties]::SetName($lab, $acc)
    [System.Windows.Automation.AutomationProperties]::SetHelpText($lab, $(if ($n.Kind -eq 'Cluster') { 'Select to expand the group' } else { 'Select to open its details' }))
    $lab.Add_MouseEnter({ param($s, $e) if (-not $s.IsEnabled) { return }; if ([string]$s.Uid -ne 'selected') { $s.SetResourceReference([System.Windows.Controls.Border]::BackgroundProperty, 'B.Hover') } })
    $lab.Add_MouseLeave({ param($s, $e) if ([string]$s.Uid -ne 'selected') { $s.SetResourceReference([System.Windows.Controls.Border]::BackgroundProperty, 'B.Card') } })
    [System.Windows.Controls.Canvas]::SetLeft($lab, $x + 34); [System.Windows.Controls.Canvas]::SetTop($lab, $y - 18)
    [System.Windows.Controls.Panel]::SetZIndex($lab, 3)
    [void]$Canvas.Children.Add($lab)
    foreach ($el in @($body, $lab)) { $el.Add_MouseLeftButtonUp({ param($s, $e) Invoke-MspkiGuiMapNodeClick -Tag ([string]$s.Tag) -Source $s; $e.Handled = $true }) }
    $dim = $(if (-not $n.Match) { 0.25 } elseif ($n.Context) { 0.6 } else { 1.0 })
    if ($dim -lt 1.0) { foreach ($el in @($body, $lab, $mark)) { if ($null -ne $el) { $el.Opacity = $dim } } }
    return [pscustomobject]@{
        Node = $n; Body = $body; Circle = $circle; Icon = $icon; Pulse = $pulse; Mark = $mark; Label = $lab; LabelEnd = ($x + 34 + $used + 10 + 4); Dim = $dim
        Fill = (Get-MspkiGuiColorOf -Key $keys[0]); Line = (Get-MspkiGuiColorOf -Key $keys[1]); Fore = (Get-MspkiGuiColorOf -Key $keys[2])
        NeutralFill = (Get-MspkiGuiColorOf -Key 'B.Card'); NeutralLine = (Get-MspkiGuiColorOf -Key 'B.BorderStrong'); NeutralFore = (Get-MspkiGuiColorOf -Key 'B.Muted')
    }
}

function New-MspkiGuiMapLinkVisual {
    <#
    .SYNOPSIS
    Adds one link to a canvas: a quiet line, the accent chain, a dashed "issuer not confirmed" line, or the path health of the address it
    leads to (failing: red dashed with a cross marker; warning: amber with a warning marker; never colour alone). A wide invisible stroke
    carries the plain-words tooltip, so the link is easy to hover.
    #>
    param([Parameter(Mandatory = $true)]$Link, [Parameter(Mandatory = $true)]$From, [Parameter(Mandatory = $true)]$To, [Parameter(Mandatory = $true)]$Canvas, [double]$Top, [double]$StartX, [hashtable]$Marked = $null)
    $w = $script:MspkiGui.Window
    $a = $From; $b = $To
    $x1 = $StartX; $y1 = [double]$a.Y + $Top
    $x2 = [double]$b.X - 3; $y2 = [double]$b.Y + $Top
    if ($x2 -le $x1 + 4) { $x1 = [double]$a.X + 26 }
    $mid = $x1 + ($x2 - $x1) * 0.5
    $c1 = $mid; $c2 = $mid
    # D-09: across a wide gap (many links), the links of one object run together as a trunk and fan out near their targets.
    if (($x2 - $x1) -gt 150) { $c1 = $x1 + ($x2 - $x1) * 0.8; $c2 = $x1 + ($x2 - $x1) * 0.55 }
    $fig = New-Object System.Windows.Media.PathFigure
    $fig.StartPoint = New-Object System.Windows.Point($x1, $y1)
    [void]$fig.Segments.Add((New-Object System.Windows.Media.BezierSegment((New-Object System.Windows.Point($c1, $y1)), (New-Object System.Windows.Point($c2, $y2)), (New-Object System.Windows.Point($x2, $y2)), $true)))
    $geo = New-Object System.Windows.Media.PathGeometry
    [void]$geo.Figures.Add($fig)
    $geo.Freeze()
    $p = New-Object System.Windows.Shapes.Path
    $p.Data = $geo; $p.SnapsToDevicePixels = $true; $p.IsHitTestVisible = $false
    $dashed = $false
    $markGlyph = 0; $markKey = ''
    switch ([string]$Link.Kind) {
        'chain' { $p.Stroke = $w.FindResource('B.Accent'); $p.StrokeThickness = 2 }
        'unconfirmed' { $p.Stroke = $w.FindResource('B.ControlStrong'); $p.StrokeThickness = 1.5; $dashed = $true; $p.StrokeDashArray = [System.Windows.Media.DoubleCollection]::Parse('3.0 3.0'); $markGlyph = 0xE9CE; $markKey = 'B.NeutralFore' }
        default {
            if ($Link.Tone -eq 'Bad') { $p.Stroke = $w.FindResource('B.BadData'); $p.StrokeThickness = 2; $dashed = $true; $p.StrokeDashArray = [System.Windows.Media.DoubleCollection]::Parse('4.0 3.0'); $markGlyph = 0xE711; $markKey = 'B.BadFore' }
            elseif ($Link.Tone -eq 'Warn') { $p.Stroke = $w.FindResource('B.WarnData'); $p.StrokeThickness = 2; $markGlyph = 0xE7BA; $markKey = 'B.WarnFore' }
            else { $p.Stroke = $w.FindResource('B.BorderStrong'); $p.StrokeThickness = 1 }
        }
    }
    [System.Windows.Controls.Panel]::SetZIndex($p, 0)
    [void]$Canvas.Children.Add($p)
    $hit = New-Object System.Windows.Shapes.Path
    $hit.Data = $geo; $hit.Stroke = [System.Windows.Media.Brushes]::Transparent; $hit.StrokeThickness = 10
    $hit.ToolTip = [string]$Link.Text
    [System.Windows.Controls.ToolTipService]::SetInitialShowDelay($hit, 250)
    [System.Windows.Automation.AutomationProperties]::SetName($hit, [string]$Link.Text)
    [System.Windows.Controls.Panel]::SetZIndex($hit, 0)
    [void]$Canvas.Children.Add($hit)
    $marker = $null
    # One marker per target and tone, near the target end of the link (78 % along it): on a dense fan the markers line up beside the
    # nodes they belong to instead of piling up in the middle.
    $mk = [string]$To.Id + '|' + $markGlyph
    if ($markGlyph -ne 0 -and $null -ne $Marked -and $Marked.ContainsKey($mk)) { $markGlyph = 0 }
    if ($markGlyph -ne 0 -and $null -ne $Marked) { $Marked[$mk] = $true }
    $tt = 0.78; $u = 1 - $tt
    $mx = $u * $u * $u * $x1 + 3 * $u * $u * $tt * $c1 + 3 * $u * $tt * $tt * $c2 + $tt * $tt * $tt * $x2
    $my = $u * $u * $u * $y1 + 3 * $u * $u * $tt * $y1 + 3 * $u * $tt * $tt * $y2 + $tt * $tt * $tt * $y2
    if ($markGlyph -ne 0) {
        $marker = New-Object System.Windows.Controls.Border
        $marker.Width = 16; $marker.Height = 16; $marker.CornerRadius = New-Object System.Windows.CornerRadius(8)
        $marker.Background = $w.FindResource($markKey); $marker.BorderBrush = $w.FindResource('B.Card'); $marker.BorderThickness = New-Object System.Windows.Thickness(1.5)
        $marker.ToolTip = [string]$Link.Text
        $mg = New-Object System.Windows.Controls.TextBlock
        $mg.Style = $w.FindResource('Glyph'); $mg.Text = [string][char]$markGlyph; $mg.FontSize = 8; $mg.FontWeight = 'Bold'; $mg.Foreground = $w.FindResource('B.OnData')
        $mg.HorizontalAlignment = 'Center'; $mg.VerticalAlignment = 'Center'
        $marker.Child = $mg
        [System.Windows.Controls.Canvas]::SetLeft($marker, $mx - 8); [System.Windows.Controls.Canvas]::SetTop($marker, $my - 8)
        [System.Windows.Controls.Panel]::SetZIndex($marker, 2)
        [void]$Canvas.Children.Add($marker)
    }
    $chord = [math]::Sqrt(($x2 - $x1) * ($x2 - $x1) + ($y2 - $y1) * ($y2 - $y1))
    return [pscustomobject]@{ Path = $p; Hit = $hit; Marker = $marker; Link = $Link; Dashed = $dashed; Length = ($chord * 1.5 + 8) / $p.StrokeThickness }
}

function Show-MspkiGuiMap {
    <#
    .SYNOPSIS
    Draws a laid-out map model on the Overview canvas (column captions at the top). Returns the drawn elements, which the build animation
    uses. Each node opens the full-page map with that node selected.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Model, [double]$Width, $Canvas = $null)
    $g = $script:MspkiGui
    $w = $g.Window
    $cv = $(if ($null -ne $Canvas) { $Canvas } else { $g.Ui.MapCanvas })
    $cv.Children.Clear()
    $cv.ClipToBounds = $true
    $height = [double]$Model.Height
    if ($height -le 0) { $height = Set-MspkiGuiMapLayout -Model $Model -Width $Width -LabelWidth 190 }
    $top = $script:MspkiGuiMapHeaderHeight
    $cv.Height = $height + $top
    $cv.Width = $Width
    $byId = @{}
    foreach ($n in $Model.Nodes) { $byId[[string]$n.Id] = $n }
    $drawn = [pscustomobject]@{ Nodes = (New-Object System.Collections.ArrayList); Links = (New-Object System.Collections.ArrayList); ById = @{} }
    foreach ($cap in (Get-MspkiGuiMapCaption -Model $Model)) {
        $t = New-Object System.Windows.Controls.TextBlock
        $t.Text = $cap.Text; $t.Style = $w.FindResource('Label')
        [System.Windows.Controls.Canvas]::SetLeft($t, [double]$cap.X); [System.Windows.Controls.Canvas]::SetTop($t, 0)
        [void]$cv.Children.Add($t)
    }
    $gap = $(if ($null -ne $Model.PSObject.Properties['Gap'] -and $Model.Gap) { [double]$Model.Gap } else { 38.0 })
    $marked = @{}
    foreach ($n in $Model.Nodes) { $d = New-MspkiGuiMapNodeVisual -Node $n -Canvas $cv -Top $top -Gap $gap; [void]$drawn.Nodes.Add($d); $drawn.ById[[string]$n.Id] = $d }
    foreach ($l in $Model.Links) {
        if (-not $drawn.ById.ContainsKey([string]$l.From) -or -not $drawn.ById.ContainsKey([string]$l.To)) { continue }
        $da = $drawn.ById[[string]$l.From]
        $lv = New-MspkiGuiMapLinkVisual -Link $l -From $byId[[string]$l.From] -To $byId[[string]$l.To] -Canvas $cv -Top $top -StartX $da.LabelEnd -Marked $marked
        $lv | Add-Member -NotePropertyName From -NotePropertyValue $byId[[string]$l.From]
        $lv | Add-Member -NotePropertyName To -NotePropertyValue $byId[[string]$l.To]
        [void]$drawn.Links.Add($lv)
    }
    return $drawn
}

function Get-MspkiGuiMapCaption {
    # Column captions: what each column holds, at the column's x.
    param([Parameter(Mandatory = $true)]$Model)
    $first = @{}; $caLayers = @{}
    foreach ($n in $Model.Nodes) {
        $l = [int]$n.Layer
        if (-not $first.ContainsKey($l)) { $first[$l] = $n }
        if ($n.Kind -in @('CA', 'Unknown')) { $caLayers[$l] = $true }
    }
    $out = @()
    foreach ($l in 0..([int]$Model.Layers - 1)) {
        if (-not $first.ContainsKey($l)) { continue }
        $f = $first[$l]
        $text = switch ([string]$f.Kind) {
            { $_ -in @('CA', 'Unknown') } { $(if ($caLayers.Count -gt 1 -and $l -eq 0) { 'Root CAs' } elseif ($caLayers.Count -gt 1) { 'Issuing CAs' } else { 'Certification authorities' }) }
            { $_ -in @('Endpoint', 'Cluster') } { 'Addresses the CAs publish' }
            default { 'Served by' }
        }
        $out += [pscustomobject]@{ Text = $text; X = [double]$f.X }
    }
    return $out
}

function New-MspkiGuiBuildPaths {
    # The property paths and easings the build animations use (created once per storyboard).
    $out = New-MspkiGuiEase -Mode Out
    return @{
        Op = New-Object System.Windows.PropertyPath([System.Windows.UIElement]::OpacityProperty)
        Sx = New-Object System.Windows.PropertyPath('(0).(1)', [System.Windows.UIElement]::RenderTransformProperty, [System.Windows.Media.ScaleTransform]::ScaleXProperty)
        Sy = New-Object System.Windows.PropertyPath('(0).(1)', [System.Windows.UIElement]::RenderTransformProperty, [System.Windows.Media.ScaleTransform]::ScaleYProperty)
        Ty = New-Object System.Windows.PropertyPath('(0).(1)', [System.Windows.UIElement]::RenderTransformProperty, [System.Windows.Media.TranslateTransform]::YProperty)
        FillC = New-Object System.Windows.PropertyPath('(0).(1)', [System.Windows.Shapes.Shape]::FillProperty, [System.Windows.Media.SolidColorBrush]::ColorProperty)
        LineC = New-Object System.Windows.PropertyPath('(0).(1)', [System.Windows.Shapes.Shape]::StrokeProperty, [System.Windows.Media.SolidColorBrush]::ColorProperty)
        ForeC = New-Object System.Windows.PropertyPath('(0).(1)', [System.Windows.Controls.TextBlock]::ForegroundProperty, [System.Windows.Media.SolidColorBrush]::ColorProperty)
        DashOff = New-Object System.Windows.PropertyPath([System.Windows.Shapes.Shape]::StrokeDashOffsetProperty)
        Out = $out; InOut = (New-MspkiGuiEase -Mode InOut)
    }
}

function New-MspkiGuiMissionStoryboard {
    <#
    .SYNOPSIS
    One Storyboard for the whole Overview build: the score ring sweeps, the area bars grow, the action rows rise in, and the map
    builds itself (CAs, then each published address with a probe pulse, then its health colour, hosts after their first address).
    -HeroOnly leaves the map out: the window then adds it in slices (Start-MspkiGuiAnimBuild), so a large map never blocks the window.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Drawn, [double]$TotalMs = 3000, [switch]$NoMap, [switch]$HeroOnly)
    $g = $script:MspkiGui
    $ui = $g.Ui
    $sb = New-Object System.Windows.Media.Animation.Storyboard
    $P = New-MspkiGuiBuildPaths
    # Score ring and number.
    $len = [double]$ui.ScoreArc.StrokeDashArray[0]
    Add-MspkiGuiKeyAnimation -Storyboard $sb -Target $ui.ScoreArc -Path $P.DashOff -StartMs 150 -DurationMs 900 -From $len -To 0 -Ease $P.InOut
    Add-MspkiGuiKeyAnimation -Storyboard $sb -Target $ui.TxtScore -Path $P.Op -StartMs 350 -DurationMs 400 -From 0 -To 1 -Ease $P.Out
    # Area bars, left to right, one after the other.
    $i = 0
    foreach ($f in @($g.AreaFills)) {
        if ($null -ne $f.Fill) { Add-MspkiGuiKeyAnimation -Storyboard $sb -Target $f.Fill -Path $P.Sx -StartMs (200 + 60 * $i) -DurationMs 500 -From 0 -To 1 -Ease $P.Out }
        Add-MspkiGuiKeyAnimation -Storyboard $sb -Target $f.Text -Path $P.Op -StartMs (200 + 60 * $i + 250) -DurationMs 250 -From 0 -To 1 -Ease $P.Out
        $i++
    }
    # Action rows rise 8 px and fade in.
    $ui.ActionList.UpdateLayout()
    for ($k = 0; $k -lt $ui.ActionList.Items.Count; $k++) {
        $c = $ui.ActionList.ItemContainerGenerator.ContainerFromIndex($k)
        if ($null -eq $c) { continue }
        $c.RenderTransform = New-Object System.Windows.Media.TranslateTransform(0, 0)
        Add-MspkiGuiKeyAnimation -Storyboard $sb -Target $c -Path $P.Op -StartMs (300 + 50 * $k) -DurationMs 220 -From 0 -To 1 -Ease $P.Out
        Add-MspkiGuiKeyAnimation -Storyboard $sb -Target $c -Path $P.Ty -StartMs (300 + 50 * $k) -DurationMs 220 -From 8 -To 0 -Ease $P.Out
    }
    $sb.Duration = New-Object System.Windows.Duration([TimeSpan]::FromMilliseconds($(if ($NoMap) { [math]::Max(1200.0, 200 + 40 * @($Drawn.Nodes).Count + 700) } else { $TotalMs })))
    if ($HeroOnly) { return $sb }
    Add-MspkiGuiMapBuildAnimation -Storyboard $sb -Drawn $Drawn -Settle:$NoMap
    return $sb
}

function Get-MspkiGuiSettleOrder {
    # The map nodes from top to bottom (the order in which their health colours settle after a live build).
    param([Parameter(Mandatory = $true)]$Drawn)
    $a = [object[]]@($Drawn.Nodes)
    $k = [double[]]@(foreach ($d in $a) { [double]$d.Node.Y * 1000 + [double]$d.Node.Layer })
    [Array]::Sort([Array]$k, [Array]$a)
    return , $a
}

function Add-MspkiGuiNodeBuild {
    <#
    .SYNOPSIS
    The build animation of one map node: it fades and grows in at its AppearMs, an address pulses when it is probed, its health colour and
    badge arrive at ResultMs. -SettleIndex (a map that was built live): only the health colour settles, staggered 40 ms by position.
    #>
    param([Parameter(Mandatory = $true)]$Storyboard, [Parameter(Mandatory = $true)]$D, [Parameter(Mandatory = $true)][hashtable]$P, [int]$SettleIndex = -1)
    $sb = $Storyboard
    $n = $D.Node
    if ($SettleIndex -ge 0) {
        $tr = 200.0 + 40 * $SettleIndex
        Add-MspkiGuiKeyAnimation -Storyboard $sb -Target $D.Circle -Path $P.FillC -StartMs $tr -DurationMs 280 -From $D.NeutralFill -To $D.Fill -Color
        Add-MspkiGuiKeyAnimation -Storyboard $sb -Target $D.Circle -Path $P.LineC -StartMs $tr -DurationMs 280 -From $D.NeutralLine -To $D.Line -Color
        Add-MspkiGuiKeyAnimation -Storyboard $sb -Target $D.Icon -Path $P.ForeC -StartMs $tr -DurationMs 280 -From $D.NeutralFore -To $D.Fore -Color
        if ($null -ne $D.Mark) { Add-MspkiGuiKeyAnimation -Storyboard $sb -Target $D.Mark -Path $P.Op -StartMs ($tr + 160) -DurationMs 200 -From 0 -To 1 -Ease $P.Out }
        return
    }
    $t0 = [double]$n.AppearMs
    $dim = [double]$D.Dim
    Add-MspkiGuiKeyAnimation -Storyboard $sb -Target $D.Body -Path $P.Op -StartMs $t0 -DurationMs 200 -From 0 -To $dim -Ease $P.Out
    Add-MspkiGuiKeyAnimation -Storyboard $sb -Target $D.Body -Path $P.Sx -StartMs $t0 -DurationMs 280 -From 0.6 -To 1 -Ease $P.Out
    Add-MspkiGuiKeyAnimation -Storyboard $sb -Target $D.Body -Path $P.Sy -StartMs $t0 -DurationMs 280 -From 0.6 -To 1 -Ease $P.Out
    Add-MspkiGuiKeyAnimation -Storyboard $sb -Target $D.Label -Path $P.Op -StartMs ($t0 + 80) -DurationMs 220 -From 0 -To $dim -Ease $P.Out
    # Health becomes known: neutral until the result time, then the status colours fade in, then the badge.
    $tr = [math]::Max([double]$n.ResultMs, $t0 + 200)
    Add-MspkiGuiKeyAnimation -Storyboard $sb -Target $D.Circle -Path $P.FillC -StartMs $tr -DurationMs 240 -From $D.NeutralFill -To $D.Fill -Color
    Add-MspkiGuiKeyAnimation -Storyboard $sb -Target $D.Circle -Path $P.LineC -StartMs $tr -DurationMs 240 -From $D.NeutralLine -To $D.Line -Color
    Add-MspkiGuiKeyAnimation -Storyboard $sb -Target $D.Icon -Path $P.ForeC -StartMs $tr -DurationMs 240 -From $D.NeutralFore -To $D.Fore -Color
    if ($null -ne $D.Mark) { Add-MspkiGuiKeyAnimation -Storyboard $sb -Target $D.Mark -Path $P.Op -StartMs ($tr + 120) -DurationMs 200 -From 0 -To $dim -Ease $P.Out }
    # A probe: two pulses expand from the address and fade out (base opacity 0, so nothing stays behind).
    if ($null -ne $D.Pulse -and [double]$n.ProbeMs -gt 0) {
        $p0 = [double]$n.ProbeMs
        $a = New-Object System.Windows.Media.Animation.DoubleAnimationUsingKeyFrames
        $s = New-Object System.Windows.Media.Animation.DoubleAnimationUsingKeyFrames
        $kt = { param($ms) [System.Windows.Media.Animation.KeyTime]::FromTimeSpan([TimeSpan]::FromMilliseconds($ms)) }
        [void]$a.KeyFrames.Add((New-Object System.Windows.Media.Animation.DiscreteDoubleKeyFrame(0.0, (& $kt 0))))
        [void]$s.KeyFrames.Add((New-Object System.Windows.Media.Animation.DiscreteDoubleKeyFrame(1.0, (& $kt 0))))
        foreach ($c in 0, 1) {
            $c0 = $p0 + 430 * $c
            [void]$a.KeyFrames.Add((New-Object System.Windows.Media.Animation.DiscreteDoubleKeyFrame(0.7, (& $kt $c0))))
            [void]$a.KeyFrames.Add((New-Object System.Windows.Media.Animation.LinearDoubleKeyFrame(0.0, (& $kt ($c0 + 420)))))
            [void]$s.KeyFrames.Add((New-Object System.Windows.Media.Animation.DiscreteDoubleKeyFrame(1.0, (& $kt $c0))))
            $e = New-Object System.Windows.Media.Animation.EasingDoubleKeyFrame([double]$D.Pulse.Tag, (& $kt ($c0 + 420))); $e.EasingFunction = $P.Out
            [void]$s.KeyFrames.Add($e)
        }
        $s2 = $s.Clone()
        foreach ($pair in @(@($a, $P.Op), @($s, $P.Sx), @($s2, $P.Sy))) {
            [System.Windows.Media.Animation.Storyboard]::SetTarget($pair[0], $D.Pulse)
            [System.Windows.Media.Animation.Storyboard]::SetTargetProperty($pair[0], $pair[1])
            $sb.Children.Add($pair[0])
        }
    }
}

function Add-MspkiGuiLinkBuild {
    # The build animation of one link: it draws in after its ends appear (a dashed one fades in instead), then its marker.
    param([Parameter(Mandatory = $true)]$Storyboard, [Parameter(Mandatory = $true)]$L, [Parameter(Mandatory = $true)][hashtable]$P)
    $path = $L.Path
    $t0 = [math]::Max([double]$L.From.AppearMs, [double]$L.To.AppearMs - 60)
    $to = [double]$path.Opacity
    if ($L.Dashed) { Add-MspkiGuiKeyAnimation -Storyboard $Storyboard -Target $path -Path $P.Op -StartMs $t0 -DurationMs 260 -From 0 -To $to -Ease $P.Out }
    else {
        $dash = New-Object System.Windows.Media.DoubleCollection
        [void]$dash.Add($L.Length); [void]$dash.Add($L.Length)
        $path.StrokeDashArray = $dash
        Add-MspkiGuiKeyAnimation -Storyboard $Storyboard -Target $path -Path $P.DashOff -StartMs $t0 -DurationMs 260 -From $L.Length -To 0 -Ease $P.Out
    }
    if ($null -ne $L.Marker) { Add-MspkiGuiKeyAnimation -Storyboard $Storyboard -Target $L.Marker -Path $P.Op -StartMs ([math]::Max($t0 + 200, [double]$L.To.ResultMs)) -DurationMs 200 -From 0 -To ([double]$L.Marker.Opacity) -Ease $P.Out }
}

function Add-MspkiGuiMapBuildAnimation {
    <#
    .SYNOPSIS
    Adds the whole map build to a storyboard at once (developer snapshots and tests; the window adds it in slices with Start-MspkiGuiAnimBuild).
    #>
    param([Parameter(Mandatory = $true)]$Storyboard, [Parameter(Mandatory = $true)]$Drawn, [switch]$Settle)
    $P = New-MspkiGuiBuildPaths
    if ($Settle) { $k = 0; foreach ($d in (Get-MspkiGuiSettleOrder -Drawn $Drawn)) { Add-MspkiGuiNodeBuild -Storyboard $Storyboard -D $d -P $P -SettleIndex $k; $k++ }; return }
    foreach ($d in $Drawn.Nodes) { Add-MspkiGuiNodeBuild -Storyboard $Storyboard -D $d -P $P }
    foreach ($l in $Drawn.Links) { Add-MspkiGuiLinkBuild -Storyboard $Storyboard -L $l -P $P }
}

function Update-MspkiGuiMission {
    <#
    .SYNOPSIS
    Fills the mission-control part of the Overview for the loaded results: score, areas, actions and the map. The map is drawn
    when the canvas has a width (the Overview may not be on screen yet); -Animate plays the build once it is drawn.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Data, [switch]$Animate)
    $g = $script:MspkiGui
    $ui = $g.Ui
    $findings = @($Data.Findings | Where-Object { $null -ne $_ })
    $completed = $true
    if ($null -ne $Data.RunInfo -and $null -ne $Data.RunInfo.PSObject.Properties['Completed']) { $completed = [bool]$Data.RunInfo.Completed }
    $hasCa = (@($Data.Inventory.EnterpriseCAs | Where-Object { $null -ne $_ }).Count -gt 0)
    $g.Score = Get-MspkiGuiHealthScore -Findings $findings -Completed $completed -HasCa $hasCa
    $g.Actions = Get-MspkiGuiNextAction -Findings $findings -Max 1000
    $g.ActionsExpanded = $false
    Update-MspkiGuiScoreView -Score $g.Score
    Update-MspkiGuiActionView -Actions $g.Actions
    # The headline: one sentence that answers "is my PKI healthy?" (journey J2).
    $ui.BannerTitle.Text = Get-MspkiGuiHeadline -Health $(if ($null -ne $g.Summary) { $g.Summary.Health } else { $null }) -Actions $g.Actions -Score $g.Score -Completed $completed -HasCa $hasCa -AsOf ([string]$g.ShownAsOf)
    $status = @{}
    foreach ($f in $findings) { $status[[string]$f.Id] = [string]$f.Status }
    # The map is computed by the background map worker (GuiMapPage.ps1); a new generation drops anything still pending for the last results.
    Reset-MspkiGuiMapPage
    $g.MapStatus = $status
    $g.MapModel = $null
    $g.MapDrawnWidth = 0; $g.MapRequestedWidth = 0
    $g.MapAnimatePending = [bool]$Animate
    # A map that was built live during the run is not built a second time: only the health colours settle (Replay plays the full build).
    $g.MapNoMapOnce = ([bool]$Animate -and [bool]$g.LiveWasShown)
    $g.LiveWasShown = $false
    $hasMap = $false
    if ($null -ne $g.Index) { foreach ($e in $g.Index.Entities.Values) { if ([string]$e.Type -in @('CA', 'CACertificate', 'Endpoint')) { $hasMap = $true; break } } }
    $g.MapHas = $hasMap
    $ui.MapCanvas.Children.Clear()
    $ui.MapCanvas.Height = $(if ($hasMap) { 240 } else { 0 })
    $ui.MapMoreStrip.Visibility = 'Collapsed'; $ui.BtnMapMore.Visibility = 'Collapsed'
    $ui.TxtMapEmpty.Visibility = $(if ($hasMap) { 'Collapsed' } else { 'Visible' })
    $ui.TxtMapEmpty.Text = $(if ($null -eq $g.Index) { 'These results were written by an older version of the tool, without the object graph, so there is no map. Run the health check again to see it.' } else { 'This run found no CA certificate or published address to draw.' })
    $ui.BtnReplay.IsEnabled = $hasMap
    $ui.MapLegend.Visibility = $(if ($hasMap) { 'Visible' } else { 'Collapsed' })
    $ui.TxtMapStats.Text = ''
    Invoke-MspkiGuiMapDraw -Force
    Update-MspkiGuiMapPage -Fit
}

function Invoke-MspkiGuiMapDraw {
    <#
    .SYNOPSIS
    Asks the map worker for the Overview map at the canvas host's width (again after a width change); it is drawn, and the build played
    when one is pending, when it arrives.
    #>
    [CmdletBinding()]
    param([switch]$Force)
    $g = $script:MspkiGui
    if ($null -eq $g -or -not $g.MapHas -or $null -eq $g.Data) { return }
    $ui = $g.Ui
    $width = [math]::Floor($ui.MapCanvasHost.ActualWidth)
    if ($width -lt 200) { return }
    if (-not $Force -and [math]::Abs($width - [double]$g.MapRequestedWidth) -lt 8) { return }
    $g.MapRequestedWidth = $width
    Request-MspkiGuiMapJob -Kind Overview -Width $width -Options @{ Threshold = $script:MspkiGuiMapClusterThreshold }
}

function Start-MspkiGuiMissionAnimation {
    <#
    .SYNOPSIS
    Plays the Overview build (also the "Replay discovery" button). With reduced motion it does nothing: the final state is already shown.
    #>
    [CmdletBinding()]
    param([switch]$NoMap)
    $g = $script:MspkiGui
    if ($null -eq $g.MapDrawn) { return }
    if (Test-MspkiGuiReducedMotion) { return }
    # The score part at once; the map part in slices (a large map never blocks the window); it starts when complete.
    $sb = New-MspkiGuiMissionStoryboard -Drawn $g.MapDrawn -TotalMs ([double]$g.MapTotalMs) -NoMap:$NoMap -HeroOnly
    if ($null -ne $g.MapAnims) { Start-MspkiGuiAnimBuild -Kind Overview -Storyboard $sb -Drawn $g.MapDrawn -Settle:$NoMap; return }
    Add-MspkiGuiMapBuildAnimation -Storyboard $sb -Drawn $g.MapDrawn -Settle:$NoMap
    if ($null -ne $g.Storyboard) { try { $g.Storyboard.Stop($g.Ui.PanelResults); $g.Storyboard.Remove($g.Ui.PanelResults) } catch { $null = $_ } }
    $g.Storyboard = $sb
    $g.Storyboard.Begin($g.Ui.PanelResults, $true)
}

function Set-MspkiGuiMissionFrame {
    <#
    .SYNOPSIS
    Developer snapshots: holds the Overview build at a given time (ms), so a mid-animation frame can be rendered.
    #>
    [CmdletBinding()]
    param([double]$Ms)
    $g = $script:MspkiGui
    if ($null -eq $g.Storyboard) { return }
    $o = $g.Ui.PanelResults
    $g.Storyboard.Pause($o)
    $g.Storyboard.SeekAlignedToLastTick($o, [TimeSpan]::FromMilliseconds($Ms), [System.Windows.Media.Animation.TimeSeekOrigin]::BeginTime)
}

function Set-MspkiGuiHeroMode {
    <#
    .SYNOPSIS
    Switches the Overview hero between the finished run (score, headline, actions, the cards below the map) and the run in progress
    (progress ring, what is being checked, the controls). There is no separate "running" panel: it is the same mission control.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][ValidateSet('Running', 'Results')][string]$Mode)
    $ui = $script:MspkiGui.Ui
    $running = ($Mode -eq 'Running')
    $ui.RunStrip.Visibility = $(if ($running) { 'Visible' } else { 'Collapsed' })
    $ui.ActionBlock.Visibility = $(if ($running) { 'Collapsed' } else { 'Visible' })
    $ui.PanelSummaryRest.Visibility = $(if ($running) { 'Collapsed' } else { 'Visible' })
    $ui.BannerMetaLine.Visibility = $(if ($running) { 'Collapsed' } else { 'Visible' })
    $ui.BtnScoreHow.Visibility = $(if ($running) { 'Collapsed' } else { 'Visible' })
    if ($running) { $ui.BannerGlyph.Visibility = 'Collapsed' }
}

function Update-MspkiGuiRunningHero {
    <#
    .SYNOPSIS
    The hero while a run is in progress (called every timer tick): the ring shows the progress, the headline says what the tool is doing,
    and one line says how much it has found so far. Scores and actions stay empty until the findings exist; the window says so.
    #>
    [CmdletBinding()]
    param()
    $g = $script:MspkiGui
    $ui = $g.Ui
    $pct = [math]::Max(0.0, [math]::Min(100.0, [double]$ui.Progress.Value))
    $ring = $ui.ScoreArc
    $circ = [math]::PI * ($ui.ScoreRing.Width - $ring.StrokeThickness) / $ring.StrokeThickness
    $dash = New-Object System.Windows.Media.DoubleCollection
    [void]$dash.Add([math]::Max(0.0001, $pct / 100.0 * $circ)); [void]$dash.Add($circ + 2)
    $ring.StrokeDashArray = $dash
    $ring.StrokeDashOffset = 0
    $ring.Stroke = $g.Window.FindResource('B.Accent')
    $ring.Visibility = 'Visible'
    $ui.TxtScore.Opacity = 1
    $ui.TxtScore.Text = '{0:0}%' -f $pct
    $ui.TxtScoreOf.Text = 'checked'
    $ui.BannerTitle.Text = 'Checking your PKI'
    $ui.BannerText.Text = 'Nothing is changed. The map below builds as objects are found; the score and what to do next appear when the run finishes.'
    $ui.TxtRunStage.Text = [string]$ui.TxtStage.Text
    $found = ''
    if ($null -ne $g.Live) { $found = Get-MspkiGuiLiveFoundText -State $g.Live }
    $ui.TxtRunFound.Text = $found
    $ui.TxtRunFound.Visibility = $(if ($found) { 'Visible' } else { 'Collapsed' })
}

function Enter-MspkiGuiRunningMode {
    <#
    .SYNOPSIS
    Starts the live mission control for a new run: the hero in its running form, empty (neutral) area rows, an empty live map.
    #>
    [CmdletBinding()]
    param()
    $g = $script:MspkiGui
    $ui = $g.Ui
    if ($null -ne $g.Storyboard) { try { $g.Storyboard.Stop($ui.PanelResults); $g.Storyboard.Remove($ui.PanelResults) } catch { $null = $_ }; $g.Storyboard = $null }
    $g.Live = New-MspkiGuiLiveState
    $g.LiveWasShown = $false
    $g.MapModel = $null; $g.MapDrawn = $null; $g.MapDrawnWidth = 0; $g.MapAnimatePending = $false; $g.MapNoMapOnce = $false; $g.MapHas = $false
    if ($null -ne $g.MapQueue) { $g.MapQueue.Clear(); $g.MapDraws.Clear(); $g.MapGen = [int]$g.MapGen + 1 }
    # Area rows in their neutral, waiting form.
    $s = Get-MspkiGuiHealthScore -Findings @() -Completed $true -HasCa $true
    foreach ($a in @($s.Areas)) {
        $a.Detail = 'Scored when the run finishes'
        $a.AccessibleName = '{0}: scored when the run finishes' -f $a.Name
        $a.Count = 0
    }
    Update-MspkiGuiScoreView -Score $s
    foreach ($b in @($ui.AreaPanel.Children)) { $b.IsEnabled = $false; $b.ToolTip = 'Scored when the run finishes.' }
    $ui.ScoreRing.ToolTip = 'Progress of the run. The health score appears when it finishes.'
    $ui.ScoreBand.Content = New-MspkiGuiPill -Text 'Checking' -Tone Info -Code 0xE895
    $ui.ScoreBand.ToolTip = 'The run is in progress.'
    $ui.ScorePartial.Visibility = 'Collapsed'
    $ui.TxtScoreReason.Visibility = 'Collapsed'
    Set-MspkiGuiHeroMode -Mode Running
    $ui.Tabs.SelectedItem = $ui.TabSummary
    $ui.PanelWelcome.Visibility = 'Collapsed'
    $ui.PanelResults.Visibility = 'Visible'
    $ui.MapCanvas.Children.Clear(); $ui.MapCanvas.Height = 0
    $ui.TxtMapEmpty.Text = 'Discovery has started. The first objects appear here as they are found.'
    $ui.TxtMapEmpty.Visibility = 'Visible'
    $ui.BtnReplay.IsEnabled = $false
    $ui.MapLegend.Visibility = 'Collapsed'
    $ui.TxtMapStats.Text = ''
    Update-MspkiGuiRunningHero
}

function Start-MspkiGuiLivePulse {
    # A repeating ring from a node while its probe runs (WPF animation: no PowerShell work per frame).
    param($Drawn)
    $pulse = $Drawn.Pulse
    if ($null -eq $pulse) { return }
    $dur = New-Object System.Windows.Duration([TimeSpan]::FromMilliseconds(1200))
    $ease = New-Object System.Windows.Media.Animation.QuadraticEase
    $ease.EasingMode = [System.Windows.Media.Animation.EasingMode]::EaseOut
    $a = New-Object System.Windows.Media.Animation.DoubleAnimation(0.7, 0.0, $dur); $a.RepeatBehavior = [System.Windows.Media.Animation.RepeatBehavior]::Forever
    $s = New-Object System.Windows.Media.Animation.DoubleAnimation(1.0, [double]$pulse.Tag, $dur); $s.RepeatBehavior = [System.Windows.Media.Animation.RepeatBehavior]::Forever; $s.EasingFunction = $ease
    $pulse.BeginAnimation([System.Windows.UIElement]::OpacityProperty, $a)
    $pulse.RenderTransform.BeginAnimation([System.Windows.Media.ScaleTransform]::ScaleXProperty, $s)
    $pulse.RenderTransform.BeginAnimation([System.Windows.Media.ScaleTransform]::ScaleYProperty, $s)
}

function Update-MspkiGuiLiveMap {
    <#
    .SYNOPSIS
    Redraws the discovery map from what the engine has announced so far. New nodes fade in (280 ms) and links draw in; a node whose
    probe is running pulses (at most six at once). Called at most every 500 ms and only when something changed. With reduced motion the
    nodes simply appear and a probed node shows a still ring.
    #>
    [CmdletBinding()]
    param()
    $g = $script:MspkiGui
    $ui = $g.Ui
    $st = $g.Live
    if ($null -eq $st) { return }
    $st.DrawnVersion = $st.Version
    $st.LastDraw = [DateTime]::Now
    $model = Get-MspkiGuiLiveMapModel -State $st
    if ($null -eq $model -or @($model.Nodes).Count -eq 0) { return }
    $width = [math]::Floor($ui.MapCanvasHost.ActualWidth)
    if ($width -lt 200) { $st.DrawnVersion = -1; return }
    $g.MapModel = $model
    $drawn = Show-MspkiGuiMap -Model $model -Width $width
    $g.MapDrawn = $drawn
    $g.MapDrawnWidth = $width
    $ui.TxtMapEmpty.Visibility = 'Collapsed'
    $ui.MapLegend.Visibility = 'Collapsed'
    $ui.TxtMapStats.Text = '{0}{1}{2}{1}Live: blue answered, amber did not answer. Health is graded when the run ends.' -f (Format-MspkiGuiCount -Count @($model.Nodes).Count -Singular 'object'), $script:MspkiGuiDot, (Format-MspkiGuiCount -Count @($model.Links).Count -Singular 'link')
    $reduced = Test-MspkiGuiReducedMotion
    $out = New-MspkiGuiEase -Mode Out
    $newIds = @{}
    $pulsing = 0
    foreach ($d in $drawn.Nodes) {
        $id = [string]$d.Node.Id
        $isNew = -not $st.Shown.ContainsKey($id)
        $st.Shown[$id] = $true
        if ($isNew) {
            $newIds[$id] = $true
            if (-not $reduced) {
                $dur = New-Object System.Windows.Duration([TimeSpan]::FromMilliseconds(280))
                $fade = New-Object System.Windows.Media.Animation.DoubleAnimation(0.0, 1.0, $dur); $fade.EasingFunction = $out
                $grow = New-Object System.Windows.Media.Animation.DoubleAnimation(0.6, 1.0, $dur); $grow.EasingFunction = $out
                $d.Body.BeginAnimation([System.Windows.UIElement]::OpacityProperty, $fade)
                $d.Body.RenderTransform.BeginAnimation([System.Windows.Media.ScaleTransform]::ScaleXProperty, $grow)
                $d.Body.RenderTransform.BeginAnimation([System.Windows.Media.ScaleTransform]::ScaleYProperty, $grow)
                $d.Label.BeginAnimation([System.Windows.UIElement]::OpacityProperty, $fade)
                if ($null -ne $d.Mark) { $d.Mark.BeginAnimation([System.Windows.UIElement]::OpacityProperty, $fade) }
            }
        }
        if ($null -ne $d.Pulse -and $st.Probes.Contains([string]$d.Node.EntityId) -and $pulsing -lt 6) {
            $pulsing++
            if ($reduced) { $d.Pulse.Opacity = 0.75; $d.Pulse.RenderTransform.ScaleX = [double]$d.Pulse.Tag; $d.Pulse.RenderTransform.ScaleY = [double]$d.Pulse.Tag } else { Start-MspkiGuiLivePulse -Drawn $d }
        }
    }
    if (-not $reduced) {
        $dur = New-Object System.Windows.Duration([TimeSpan]::FromMilliseconds(260))
        foreach ($l in $drawn.Links) {
            if ($newIds.ContainsKey([string]$l.From.Id) -or $newIds.ContainsKey([string]$l.To.Id)) {
                $fade = New-Object System.Windows.Media.Animation.DoubleAnimation(0.0, 1.0, $dur); $fade.EasingFunction = $out
                $l.Path.BeginAnimation([System.Windows.UIElement]::OpacityProperty, $fade)
            }
        }
    }
}
