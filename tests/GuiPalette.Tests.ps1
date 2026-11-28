# Command palette (GX4): pages, commands, objects and findings in one search (src/Gui/GuiPalette.ps1). Pure functions: no window needed.

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $script:RepoRoot 'src\MspkiHealthCheck.psd1') -Force
    foreach ($f in 'GuiModel.ps1', 'GuiView.ps1', 'GuiPalette.ps1') { . (Join-Path $script:RepoRoot ('src\Gui\' + $f)) }
    $script:Row = {
        param([string]$Id, [string]$Category, [string]$Target, [string]$Message, [string]$Status = 'Fail')
        [pscustomobject]@{ Id = $Id; Category = $Category; Target = $Target; Message = $Message; Status = $Status; StatusPill = $null
            SearchText = (@($Id, $Status, $Category, $Target, $Message) -join ' ').ToLowerInvariant() }
    }
    $script:Obj = {
        param([string]$Id, [string]$Name, [string]$TypeText)
        [pscustomobject]@{ Id = $Id; Name = $Name; TypeText = $TypeText; Glyph = ''; SearchText = (@($Name, $Id, $TypeText) -join ' ').ToLowerInvariant() }
    }
}

Describe 'Palette content' {
    It 'lists the eight pages with their Ctrl+n shortcut' {
        $p = @(Get-MspkiGuiPalettePage)
        $p.Count | Should -Be 8
        $p[0].Action | Should -Be 'page:0'
        $p[7].Shortcut | Should -Be 'Ctrl+8'
        $p[6].Title | Should -Be 'Go to History'
        $p[3].Title | Should -Be 'Go to Timeline'; $p[3].Shortcut | Should -Be 'Ctrl+4'
        $p[1].Title | Should -Be 'Go to Findings'
    }
    It 'offers every command of the command bar and leaves out what is not available now' {
        $all = @(Get-MspkiGuiPaletteCommand)
        foreach ($a in 'cmd:run', 'cmd:cancel', 'cmd:open', 'cmd:report', 'cmd:folder', 'cmd:export') { @($all.Action) | Should -Contain $a }
        $some = @(Get-MspkiGuiPaletteCommand -Available @{ cancel = $false; report = $false; run = $true })
        @($some.Action) | Should -Not -Contain 'cmd:cancel'
        @($some.Action) | Should -Not -Contain 'cmd:report'
        @($some.Action) | Should -Contain 'cmd:run'
    }
    It 'gives every item an accessible name' {
        foreach ($i in @(Get-MspkiGuiPalettePage) + @(Get-MspkiGuiPaletteCommand)) { $i.AutomationName | Should -Match '^(Page|Command): .+' }
    }
    It 'indexes findings by text and objects by name' {
        $ix = Get-MspkiGuiPaletteIndex -Rows @((& $script:Row 'F1' 'CRL' 'Issuing CA' 'The CRL has expired')) -ObjRows @((& $script:Obj 'h1' 'pki.example.test' 'Host'))
        @($ix).Count | Should -Be 2
        $ix[0].Action | Should -Be 'finding:F1'
        $ix[0].Title | Should -Be 'The CRL has expired'
        $ix[0].Detail | Should -Be ('The CRL has expired {0} F1' -f [char]0x00B7)
        $ix[1].Action | Should -Be 'ent:h1'
        $ix[1].Kind | Should -Be 'Object'
    }
}

Describe 'Find-MspkiGuiPaletteItem' {
    BeforeAll {
        $script:Fixed = @(Get-MspkiGuiPaletteCommand) + @(Get-MspkiGuiPalettePage)
        $script:Items = Get-MspkiGuiPaletteIndex -Rows @(
            (& $script:Row 'F1' 'CRL' 'Issuing CA' 'The CRL has expired'),
            (& $script:Row 'F2' 'AIA' 'pki.example.test' 'The host name does not resolve' 'Warning')
        ) -ObjRows @((& $script:Obj 'h1' 'pki.example.test' 'Host'), (& $script:Obj 'c1' 'Example Issuing CA' 'CA'))
    }
    It 'shows the commands first and then the pages for an empty query' {
        $r = @(Find-MspkiGuiPaletteItem -Query '' -Fixed $script:Fixed -Items $script:Items)
        $r[0].Kind | Should -Be 'Command'
        @($r | Where-Object Kind -eq 'Finding').Count | Should -Be 0
        @($r | Where-Object Kind -eq 'Page').Count | Should -Be 8
    }
    It 'finds a page by its name' {
        (@(Find-MspkiGuiPaletteItem -Query 'objects' -Fixed $script:Fixed -Items $script:Items))[0].Action | Should -Be 'page:4'
        (@(Find-MspkiGuiPaletteItem -Query 'map' -Fixed $script:Fixed -Items $script:Items))[0].Action | Should -Be 'page:2'
    }
    It 'finds a command by a word of its title or a synonym' {
        (@(Find-MspkiGuiPaletteItem -Query 'run' -Fixed $script:Fixed -Items $script:Items))[0].Action | Should -Be 'cmd:run'
        @(Find-MspkiGuiPaletteItem -Query 'csv' -Fixed $script:Fixed -Items $script:Items).Action | Should -Contain 'cmd:export'
    }
    It 'finds a finding by text in its message and needs every word' {
        $r = @(Find-MspkiGuiPaletteItem -Query 'crl expired' -Fixed $script:Fixed -Items $script:Items)
        @($r.Action) | Should -Contain 'finding:F1'
        @($r.Action) | Should -Not -Contain 'finding:F2'
        @(Find-MspkiGuiPaletteItem -Query 'crl nothing-like-this' -Fixed $script:Fixed -Items $script:Items).Count | Should -Be 0
    }
    It 'finds an object by name, title match before a match in the text' {
        $r = @(Find-MspkiGuiPaletteItem -Query 'pki.example.test' -Fixed $script:Fixed -Items $script:Items)
        $r[0].Action | Should -Be 'ent:h1'
        @($r.Action) | Should -Contain 'finding:F2'
    }
    It 'ignores case and extra spaces' {
        (@(Find-MspkiGuiPaletteItem -Query '  ISSUING   ca ' -Fixed $script:Fixed -Items $script:Items))[0].Action | Should -Be 'ent:c1'
    }
    It 'stops at Max' {
        @(Find-MspkiGuiPaletteItem -Query 'e' -Fixed $script:Fixed -Items $script:Items -Max 3).Count | Should -Be 3
    }
    It 'searches 5000 items quickly enough to run on each key press (under 400 ms here, a debounce covers the rest)' {
        $rows = @(foreach ($i in 1..2500) { & $script:Row ('F{0}' -f $i) 'CRL' ('Target {0}' -f $i) ('Message number {0} about a CRL' -f $i) })
        $objs = @(foreach ($i in 1..2500) { & $script:Obj ('o{0}' -f $i) ('host{0}.example.test' -f $i) 'Host' })
        $big = Get-MspkiGuiPaletteIndex -Rows $rows -ObjRows $objs
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $r = @(Find-MspkiGuiPaletteItem -Query 'host12' -Fixed $script:Fixed -Items $big)
        $sw.Stop()
        $r.Count | Should -BeGreaterThan 0
        $sw.ElapsedMilliseconds | Should -BeLessThan 400
    }
}
