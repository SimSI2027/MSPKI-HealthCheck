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
    $ui.TxtScoreReason.Text = $(if ($Score.HasScore) { '' } else { [string]$Score.Reason })
    $ui.TxtScoreReason.Visibility = $(if ($Score.HasScore) { 'Collapsed' } else { 'Visible' })

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
        foreach ($w in @(20, 128, -1, 36)) {
            $cd = New-Object System.Windows.Controls.ColumnDefinition
            $cd.Width = $(if ($w -lt 0) { New-Object System.Windows.GridLength(1, [System.Windows.GridUnitType]::Star) } else { New-Object System.Windows.GridLength($w) })
            $grid.ColumnDefinitions.Add($cd)
        }
        $k = $script:MspkiGuiToneKeys[[string]$a.Tone]
        $gl = New-Object System.Windows.Controls.TextBlock
        $gl.Style = $g.Window.FindResource('Glyph'); $gl.Text = [string]$a.Glyph; $gl.FontSize = 12; $gl.Foreground = $g.Window.FindResource($k[2]); $gl.VerticalAlignment = 'Center'
        $nm = New-Object System.Windows.Controls.TextBlock
        $nm.Text = [string]$a.Name; $nm.TextTrimming = 'CharacterEllipsis'; $nm.VerticalAlignment = 'Center'
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

function Show-MspkiGuiMap {
    <#
    .SYNOPSIS
    Draws the discovery map model on the Overview canvas for the canvas's current width. Returns the drawn elements, which the
    build animation uses. Column captions sit at the top; each node opens its object details when selected.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Model, [double]$Width)
    $g = $script:MspkiGui
    $w = $g.Window
    $cv = $g.Ui.MapCanvas
    $cv.Children.Clear()
    $height = Set-MspkiGuiMapLayout -Model $Model -Width $Width -LabelWidth 190
    $top = $script:MspkiGuiMapHeaderHeight
    $cv.Height = $height + $top
    $cv.Width = $Width
    $byId = @{}
    foreach ($n in $Model.Nodes) { $byId[$n.Id] = $n }
    $drawn = [pscustomobject]@{ Nodes = (New-Object System.Collections.ArrayList); Links = (New-Object System.Collections.ArrayList) }

    # Column captions: what each column holds.
    $caLayers = @($Model.Nodes | Where-Object { $_.Kind -eq 'CA' } | ForEach-Object { [int]$_.Layer } | Select-Object -Unique)
    foreach ($l in 0..([int]$Model.Layers - 1)) {
        $first = @($Model.Nodes | Where-Object { [int]$_.Layer -eq $l })[0]
        if ($null -eq $first) { continue }
        $cap = switch ([string]$first.Kind) {
            'CA' { $(if ($caLayers.Count -gt 1 -and $l -eq 0) { 'Root CAs' } elseif ($caLayers.Count -gt 1) { 'Issuing CAs' } else { 'Certification authorities' }) }
            'Endpoint' { 'Addresses the CAs publish' }
            default { 'Served by' }
        }
        $t = New-Object System.Windows.Controls.TextBlock
        $t.Text = $cap; $t.Style = $w.FindResource('Label')
        [System.Windows.Controls.Canvas]::SetLeft($t, [double]$first.X); [System.Windows.Controls.Canvas]::SetTop($t, 0)
        [void]$cv.Children.Add($t)
    }

    # Labels first (measured), so that each link can start where its label text ends.
    $labelEnd = @{}
    $labels = @{}
    foreach ($n in $Model.Nodes) {
        $sp = New-Object System.Windows.Controls.StackPanel
        $sp.Width = [math]::Max(40.0, [double]$n.LabelWidth)
        $t1 = New-Object System.Windows.Controls.TextBlock
        $t1.Text = [string]$n.Label; $t1.FontWeight = 'SemiBold'; $t1.FontSize = 12; $t1.TextTrimming = 'CharacterEllipsis'
        $t2 = New-Object System.Windows.Controls.TextBlock
        $t2.Text = [string]$n.Sub; $t2.Style = $w.FindResource('Small'); $t2.TextTrimming = 'CharacterEllipsis'
        [void]$sp.Children.Add($t1); [void]$sp.Children.Add($t2)
        $used = [math]::Min($sp.Width, [math]::Max((Measure-MspkiGuiTextWidth -TextBlock $t1), (Measure-MspkiGuiTextWidth -TextBlock $t2)))
        $labelEnd[$n.Id] = [double]$n.X + 32 + $used + 6
        $labels[$n.Id] = $sp
    }
    # Links (under the nodes): a chain link in the accent colour, the others as quiet lines.
    foreach ($l in $Model.Links) {
        if (-not $byId.ContainsKey($l.From) -or -not $byId.ContainsKey($l.To)) { continue }
        $a = $byId[$l.From]; $b = $byId[$l.To]
        $x1 = $labelEnd[$a.Id]; $y1 = [double]$a.Y + $top
        $x2 = [double]$b.X - 3; $y2 = [double]$b.Y + $top
        if ($x2 -le $x1 + 4) { $x1 = [double]$a.X + 26 }
        $mid = $x1 + ($x2 - $x1) * 0.5
        $fig = New-Object System.Windows.Media.PathFigure
        $fig.StartPoint = New-Object System.Windows.Point($x1, $y1)
        [void]$fig.Segments.Add((New-Object System.Windows.Media.BezierSegment((New-Object System.Windows.Point($mid, $y1)), (New-Object System.Windows.Point($mid, $y2)), (New-Object System.Windows.Point($x2, $y2)), $true)))
        $geo = New-Object System.Windows.Media.PathGeometry
        [void]$geo.Figures.Add($fig)
        $p = New-Object System.Windows.Shapes.Path
        $p.Data = $geo
        $p.SnapsToDevicePixels = $true
        if ($l.Kind -eq 'chain') { $p.Stroke = $w.FindResource('B.Accent'); $p.StrokeThickness = 2 }
        else { $p.Stroke = $w.FindResource('B.BorderStrong'); $p.StrokeThickness = 1 }
        $p.ToolTip = $(switch ($l.Kind) { 'chain' { 'Issued by (certificate chain)' } 'publishes' { 'Published in the CA''s certificates or properties' } default { 'Served by this host' } })
        $chord = [math]::Sqrt(($x2 - $x1) * ($x2 - $x1) + ($y2 - $y1) * ($y2 - $y1))
        [void]$cv.Children.Add($p)
        [void]$drawn.Links.Add([pscustomobject]@{ Path = $p; From = $a; To = $b; Length = ($chord * 1.5 + 8) / $p.StrokeThickness })
    }
    # Nodes: hover area, probe pulse, circle with icon, status badge (icon, never colour alone), label.
    $neutralFill = Get-MspkiGuiColorOf -Key 'B.Card'
    $neutralLine = Get-MspkiGuiColorOf -Key 'B.BorderStrong'
    $neutralFore = Get-MspkiGuiColorOf -Key 'B.Muted'
    $badge = @{ Bad = 0xE711; Warn = 0xE7BA; Admin = 0xE72E }
    $toneWord = @{ Good = 'healthy'; Warn = 'warning'; Bad = 'failing'; Admin = 'could not be checked'; Neutral = 'no finding'; Info = 'information' }
    foreach ($n in $Model.Nodes) {
        $x = [double]$n.X; $y = [double]$n.Y + $top
        $keys = $script:MspkiGuiToneKeys[[string]$n.Tone]
        $hit = New-Object System.Windows.Controls.Border
        $hit.Width = 32 + [double]$labels[$n.Id].Width + 6; $hit.Height = 36
        $hit.CornerRadius = New-Object System.Windows.CornerRadius(6)
        $hit.Background = [System.Windows.Media.Brushes]::Transparent
        $hit.Cursor = [System.Windows.Input.Cursors]::Hand
        $hit.Tag = 'ent:' + [string]$n.EntityId
        $hit.ToolTip = '{0}{1}{2}: {3}. Select to open it.' -f [string]$n.FullName, [Environment]::NewLine, [string]$n.Sub, $toneWord[[string]$n.Tone]
        [System.Windows.Automation.AutomationProperties]::SetName($hit, ('{0}, {1}, {2}' -f [string]$n.Label, [string]$n.Sub, $toneWord[[string]$n.Tone]))
        $hit.Add_MouseEnter({ param($s, $e) $s.Background = $script:MspkiGui.Window.FindResource('B.Hover') })
        $hit.Add_MouseLeave({ param($s, $e) $s.Background = [System.Windows.Media.Brushes]::Transparent })
        $hit.Add_MouseLeftButtonUp({ param($s, $e) $t = [string]$s.Tag; if ($t.StartsWith('ent:')) { Show-MspkiGuiObject -Id $t.Substring(4) } })
        [System.Windows.Controls.Canvas]::SetLeft($hit, $x - 4); [System.Windows.Controls.Canvas]::SetTop($hit, $y - 18)
        [void]$cv.Children.Add($hit)

        $pulse = $null
        if ($n.Kind -in @('Endpoint', 'Host')) {
            $pulse = New-Object System.Windows.Shapes.Ellipse
            $pulse.Width = 26; $pulse.Height = 26; $pulse.Stroke = $w.FindResource('B.Accent'); $pulse.StrokeThickness = 2
            $pulse.Opacity = 0; $pulse.IsHitTestVisible = $false
            $pulse.RenderTransformOrigin = New-Object System.Windows.Point(0.5, 0.5)
            $pulse.RenderTransform = New-Object System.Windows.Media.ScaleTransform(1, 1)
            [System.Windows.Controls.Canvas]::SetLeft($pulse, $x); [System.Windows.Controls.Canvas]::SetTop($pulse, $y - 13)
            [void]$cv.Children.Add($pulse)
        }
        $body = New-Object System.Windows.Controls.Grid
        $body.Width = 26; $body.Height = 26; $body.IsHitTestVisible = $false
        $body.RenderTransformOrigin = New-Object System.Windows.Point(0.5, 0.5)
        $body.RenderTransform = New-Object System.Windows.Media.ScaleTransform(1, 1)
        $circle = New-Object System.Windows.Shapes.Ellipse
        $circle.Fill = New-MspkiGuiBrushOf -Key $keys[0]
        $circle.Stroke = New-MspkiGuiBrushOf -Key $keys[1]
        $circle.StrokeThickness = 1.5
        $icon = New-Object System.Windows.Controls.TextBlock
        $icon.Style = $w.FindResource('Glyph'); $icon.Text = [string]$n.Glyph; $icon.FontSize = 12
        $icon.Foreground = New-MspkiGuiBrushOf -Key $keys[2]
        $icon.HorizontalAlignment = 'Center'; $icon.VerticalAlignment = 'Center'
        [void]$body.Children.Add($circle); [void]$body.Children.Add($icon)
        [System.Windows.Controls.Canvas]::SetLeft($body, $x); [System.Windows.Controls.Canvas]::SetTop($body, $y - 13)
        [void]$cv.Children.Add($body)

        $mark = $null
        if ($badge.ContainsKey([string]$n.Tone)) {
            $mark = New-Object System.Windows.Controls.Border
            $mark.Width = 16; $mark.Height = 16; $mark.CornerRadius = New-Object System.Windows.CornerRadius(8)
            $mark.Background = $w.FindResource($keys[2]); $mark.BorderBrush = $w.FindResource('B.Card'); $mark.BorderThickness = New-Object System.Windows.Thickness(1.5)
            $mark.IsHitTestVisible = $false
            $mg = New-Object System.Windows.Controls.TextBlock
            $mg.Style = $w.FindResource('Glyph'); $mg.Text = [string][char]$badge[[string]$n.Tone]; $mg.FontSize = 9; $mg.FontWeight = 'Bold'; $mg.Foreground = $w.FindResource('B.White')
            $mg.HorizontalAlignment = 'Center'; $mg.VerticalAlignment = 'Center'
            $mark.Child = $mg
            [System.Windows.Controls.Canvas]::SetLeft($mark, $x + 15); [System.Windows.Controls.Canvas]::SetTop($mark, $y - 19)
            [void]$cv.Children.Add($mark)
        }
        $lab = $labels[$n.Id]
        $lab.IsHitTestVisible = $false
        [System.Windows.Controls.Canvas]::SetLeft($lab, $x + 32); [System.Windows.Controls.Canvas]::SetTop($lab, $y - 16)
        [void]$cv.Children.Add($lab)
        [void]$drawn.Nodes.Add([pscustomobject]@{
            Node = $n; Body = $body; Circle = $circle; Icon = $icon; Pulse = $pulse; Mark = $mark; Label = $lab
            Fill = (Get-MspkiGuiColorOf -Key $keys[0]); Line = (Get-MspkiGuiColorOf -Key $keys[1]); Fore = (Get-MspkiGuiColorOf -Key $keys[2])
            NeutralFill = $neutralFill; NeutralLine = $neutralLine; NeutralFore = $neutralFore
        })
    }
    return $drawn
}

function New-MspkiGuiMissionStoryboard {
    <#
    .SYNOPSIS
    One Storyboard for the whole Overview build: the score ring sweeps, the area bars grow, the action rows rise in, and the map
    builds itself (CAs, then each published address with a probe pulse, then its health colour, hosts after their first address).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Drawn, [double]$TotalMs = 3000, [switch]$NoMap)
    $g = $script:MspkiGui
    $ui = $g.Ui
    $sb = New-Object System.Windows.Media.Animation.Storyboard
    $op = New-Object System.Windows.PropertyPath([System.Windows.UIElement]::OpacityProperty)
    $sx = New-Object System.Windows.PropertyPath('(0).(1)', [System.Windows.UIElement]::RenderTransformProperty, [System.Windows.Media.ScaleTransform]::ScaleXProperty)
    $sy = New-Object System.Windows.PropertyPath('(0).(1)', [System.Windows.UIElement]::RenderTransformProperty, [System.Windows.Media.ScaleTransform]::ScaleYProperty)
    $ty = New-Object System.Windows.PropertyPath('(0).(1)', [System.Windows.UIElement]::RenderTransformProperty, [System.Windows.Media.TranslateTransform]::YProperty)
    $fillC = New-Object System.Windows.PropertyPath('(0).(1)', [System.Windows.Shapes.Shape]::FillProperty, [System.Windows.Media.SolidColorBrush]::ColorProperty)
    $lineC = New-Object System.Windows.PropertyPath('(0).(1)', [System.Windows.Shapes.Shape]::StrokeProperty, [System.Windows.Media.SolidColorBrush]::ColorProperty)
    $foreC = New-Object System.Windows.PropertyPath('(0).(1)', [System.Windows.Controls.TextBlock]::ForegroundProperty, [System.Windows.Media.SolidColorBrush]::ColorProperty)
    $dashOff = New-Object System.Windows.PropertyPath([System.Windows.Shapes.Shape]::StrokeDashOffsetProperty)
    $out = New-MspkiGuiEase -Mode Out
    $inOut = New-MspkiGuiEase -Mode InOut

    # Score ring and number.
    $len = [double]$ui.ScoreArc.StrokeDashArray[0]
    Add-MspkiGuiKeyAnimation -Storyboard $sb -Target $ui.ScoreArc -Path $dashOff -StartMs 150 -DurationMs 900 -From $len -To 0 -Ease $inOut
    Add-MspkiGuiKeyAnimation -Storyboard $sb -Target $ui.TxtScore -Path $op -StartMs 350 -DurationMs 400 -From 0 -To 1 -Ease $out
    # Area bars, left to right, one after the other.
    $i = 0
    foreach ($f in @($g.AreaFills)) {
        if ($null -ne $f.Fill) { Add-MspkiGuiKeyAnimation -Storyboard $sb -Target $f.Fill -Path $sx -StartMs (200 + 60 * $i) -DurationMs 500 -From 0 -To 1 -Ease $out }
        Add-MspkiGuiKeyAnimation -Storyboard $sb -Target $f.Text -Path $op -StartMs (200 + 60 * $i + 250) -DurationMs 250 -From 0 -To 1 -Ease $out
        $i++
    }
    # Action rows rise 8 px and fade in.
    $ui.ActionList.UpdateLayout()
    for ($k = 0; $k -lt $ui.ActionList.Items.Count; $k++) {
        $c = $ui.ActionList.ItemContainerGenerator.ContainerFromIndex($k)
        if ($null -eq $c) { continue }
        $c.RenderTransform = New-Object System.Windows.Media.TranslateTransform(0, 0)
        Add-MspkiGuiKeyAnimation -Storyboard $sb -Target $c -Path $op -StartMs (300 + 50 * $k) -DurationMs 220 -From 0 -To 1 -Ease $out
        Add-MspkiGuiKeyAnimation -Storyboard $sb -Target $c -Path $ty -StartMs (300 + 50 * $k) -DurationMs 220 -From 8 -To 0 -Ease $out
    }
    # The map was built live during the run (-NoMap): the nodes are already there, so only their health colour fades from the
    # neutral live look to the graded one (staggered 40 ms), then the badge.
    if ($NoMap) {
        $k = 0
        foreach ($d in @($Drawn.Nodes | Sort-Object { [double]$_.Node.Y })) {
            $tr = 200.0 + 40 * $k; $k++
            Add-MspkiGuiKeyAnimation -Storyboard $sb -Target $d.Circle -Path $fillC -StartMs $tr -DurationMs 280 -From $d.NeutralFill -To $d.Fill -Color
            Add-MspkiGuiKeyAnimation -Storyboard $sb -Target $d.Circle -Path $lineC -StartMs $tr -DurationMs 280 -From $d.NeutralLine -To $d.Line -Color
            Add-MspkiGuiKeyAnimation -Storyboard $sb -Target $d.Icon -Path $foreC -StartMs $tr -DurationMs 280 -From $d.NeutralFore -To $d.Fore -Color
            if ($null -ne $d.Mark) { Add-MspkiGuiKeyAnimation -Storyboard $sb -Target $d.Mark -Path $op -StartMs ($tr + 160) -DurationMs 200 -From 0 -To 1 -Ease $out }
        }
        $sb.Duration = New-Object System.Windows.Duration([TimeSpan]::FromMilliseconds([math]::Max(1200.0, 200 + 40 * $k + 700)))
        return $sb
    }
    # The map builds itself.
    foreach ($d in $Drawn.Nodes) {
        $n = $d.Node
        $t0 = [double]$n.AppearMs
        Add-MspkiGuiKeyAnimation -Storyboard $sb -Target $d.Body -Path $op -StartMs $t0 -DurationMs 200 -From 0 -To 1 -Ease $out
        Add-MspkiGuiKeyAnimation -Storyboard $sb -Target $d.Body -Path $sx -StartMs $t0 -DurationMs 280 -From 0.6 -To 1 -Ease $out
        Add-MspkiGuiKeyAnimation -Storyboard $sb -Target $d.Body -Path $sy -StartMs $t0 -DurationMs 280 -From 0.6 -To 1 -Ease $out
        Add-MspkiGuiKeyAnimation -Storyboard $sb -Target $d.Label -Path $op -StartMs ($t0 + 80) -DurationMs 220 -From 0 -To 1 -Ease $out
        # Health becomes known: neutral until the result time, then the status colours fade in, then the badge.
        $tr = [math]::Max([double]$n.ResultMs, $t0 + 200)
        Add-MspkiGuiKeyAnimation -Storyboard $sb -Target $d.Circle -Path $fillC -StartMs $tr -DurationMs 240 -From $d.NeutralFill -To $d.Fill -Color
        Add-MspkiGuiKeyAnimation -Storyboard $sb -Target $d.Circle -Path $lineC -StartMs $tr -DurationMs 240 -From $d.NeutralLine -To $d.Line -Color
        Add-MspkiGuiKeyAnimation -Storyboard $sb -Target $d.Icon -Path $foreC -StartMs $tr -DurationMs 240 -From $d.NeutralFore -To $d.Fore -Color
        if ($null -ne $d.Mark) { Add-MspkiGuiKeyAnimation -Storyboard $sb -Target $d.Mark -Path $op -StartMs ($tr + 120) -DurationMs 200 -From 0 -To 1 -Ease $out }
        # A probe: two pulses expand from the address and fade out (base opacity 0, so nothing stays behind).
        if ($null -ne $d.Pulse -and [double]$n.ProbeMs -gt 0) {
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
                $e = New-Object System.Windows.Media.Animation.EasingDoubleKeyFrame(2.3, (& $kt ($c0 + 420))); $e.EasingFunction = $out
                [void]$s.KeyFrames.Add($e)
            }
            $s2 = $s.Clone()
            foreach ($pair in @(@($a, $op), @($s, $sx), @($s2, $sy))) {
                [System.Windows.Media.Animation.Storyboard]::SetTarget($pair[0], $d.Pulse)
                [System.Windows.Media.Animation.Storyboard]::SetTargetProperty($pair[0], $pair[1])
                $sb.Children.Add($pair[0])
            }
        }
    }
    foreach ($l in $Drawn.Links) {
        $p = $l.Path
        $dash = New-Object System.Windows.Media.DoubleCollection
        [void]$dash.Add($l.Length); [void]$dash.Add($l.Length)
        $p.StrokeDashArray = $dash
        $t0 = [math]::Max([double]$l.From.AppearMs, [double]$l.To.AppearMs - 60)
        Add-MspkiGuiKeyAnimation -Storyboard $sb -Target $p -Path $dashOff -StartMs $t0 -DurationMs 260 -From $l.Length -To 0 -Ease $out
    }
    $sb.Duration = New-Object System.Windows.Duration([TimeSpan]::FromMilliseconds($TotalMs))
    return $sb
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
    $ui.BannerTitle.Text = Get-MspkiGuiHeadline -Health $(if ($null -ne $g.Summary) { $g.Summary.Health } else { $null }) -Actions $g.Actions -Score $g.Score -Completed $completed -HasCa $hasCa
    $status = @{}
    foreach ($f in $findings) { $status[[string]$f.Id] = [string]$f.Status }
    $g.MapModel = Get-MspkiGuiMapModel -Index $g.Index -FindingStatus $status
    $g.MapDrawnWidth = 0
    $g.MapAnimatePending = [bool]$Animate
    # A map that was built live during the run is not built a second time: only the health colours settle (Replay plays the full build).
    $g.MapNoMapOnce = ([bool]$Animate -and [bool]$g.LiveWasShown)
    $g.LiveWasShown = $false
    $hasMap =($null -ne $g.MapModel -and @($g.MapModel.Nodes).Count -gt 0)
    $ui.MapCanvas.Children.Clear()
    $ui.MapCanvas.Height = $(if ($hasMap) { 240 } else { 0 })
    $ui.TxtMapEmpty.Visibility = $(if ($hasMap) { 'Collapsed' } else { 'Visible' })
    $ui.TxtMapEmpty.Text = $(if ($null -eq $g.Index) { 'These results were written by an older version of the tool, without the object graph, so there is no map. Run the health check again to see it.' } else { 'This run found no CA certificate or published address to draw.' })
    $ui.BtnReplay.IsEnabled = $hasMap
    $ui.MapLegend.Visibility = $(if ($hasMap) { 'Visible' } else { 'Collapsed' })
    $ui.TxtMapStats.Text = $(if ($hasMap) { '{0}{1}{2}' -f (Format-MspkiGuiCount -Count @($g.MapModel.Nodes).Count -Singular 'object'), $script:MspkiGuiDot, (Format-MspkiGuiCount -Count @($g.MapModel.Links).Count -Singular 'link') } else { '' })
    Invoke-MspkiGuiMapDraw
}

function Invoke-MspkiGuiMapDraw {
    <#
    .SYNOPSIS
    Draws (or redraws, after a width change) the map for the canvas host's width; plays the build when one is pending.
    #>
    [CmdletBinding()]
    param([switch]$Force)
    $g = $script:MspkiGui
    if ($null -eq $g -or $null -eq $g.MapModel -or @($g.MapModel.Nodes).Count -eq 0) { return }
    $ui = $g.Ui
    $width = [math]::Floor($ui.MapCanvasHost.ActualWidth)
    if ($width -lt 200) { return }
    if (-not $Force -and [math]::Abs($width - [double]$g.MapDrawnWidth) -lt 8 -and -not $g.MapAnimatePending) { return }
    if ($null -ne $g.Storyboard) { try { $g.Storyboard.Stop($ui.PanelResults); $g.Storyboard.Remove($ui.PanelResults) } catch { $null = $_ } ; $g.Storyboard = $null }
    $g.MapDrawn = Show-MspkiGuiMap -Model $g.MapModel -Width $width
    $g.MapDrawnWidth = $width
    $g.MapTotalMs = Set-MspkiGuiMapTimeline -Model $g.MapModel
    if ($g.MapAnimatePending) {
        $g.MapAnimatePending = $false
        $noMap = [bool]$g.MapNoMapOnce
        $g.MapNoMapOnce = $false
        Start-MspkiGuiMissionAnimation -NoMap:$noMap
    }
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
    if ($null -ne $g.Storyboard) { try { $g.Storyboard.Stop($g.Ui.PanelResults); $g.Storyboard.Remove($g.Ui.PanelResults) } catch { $null = $_ } }
    $g.Storyboard = New-MspkiGuiMissionStoryboard -Drawn $g.MapDrawn -TotalMs ([double]$g.MapTotalMs) -NoMap:$NoMap
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
    $g.MapModel = $null; $g.MapDrawn = $null; $g.MapDrawnWidth = 0; $g.MapAnimatePending = $false; $g.MapNoMapOnce = $false
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
    $s = New-Object System.Windows.Media.Animation.DoubleAnimation(1.0, 2.3, $dur); $s.RepeatBehavior = [System.Windows.Media.Animation.RepeatBehavior]::Forever; $s.EasingFunction = $ease
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
            if ($reduced) { $d.Pulse.Opacity = 0.75; $d.Pulse.RenderTransform.ScaleX = 1.45; $d.Pulse.RenderTransform.ScaleY = 1.45 } else { Start-MspkiGuiLivePulse -Drawn $d }
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
