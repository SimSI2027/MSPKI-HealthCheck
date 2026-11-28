# Deterministic finding keys (GX8): the same check of the same thing gets the same Key in every run, so two runs can be compared.
# The Id (F0001...) is only the order within one run; the Key is what stays.

function Get-MspkiFindingIdentity {
    <#
    .SYNOPSIS
    The text a finding's Key is made from: key version, category, status code, rule (the knowledge topic of a finding that is not passing),
    target and endpoint. Target and endpoint are trimmed and lower-cased so a name written in another case is the same thing.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Finding, $Knowledge = $null)
    $rule = ''
    if ($null -ne $Finding.PSObject.Properties['Diagnosis'] -and $null -ne $Finding.Diagnosis -and $null -ne $Finding.Diagnosis.PSObject.Properties['Topic']) { $rule = [string]$Finding.Diagnosis.Topic }
    elseif (Test-MspkiFindingNeedsDiagnosis -Finding $Finding) {
        # Results written before the Key existed carry no Diagnosis everywhere: the rule is resolved the same way the run resolves it.
        try { $r = Resolve-MspkiDiagnosisTopic -Finding $Finding -Knowledge $Knowledge; if ($null -ne $r) { $rule = [string]$r.Topic } } catch { $rule = '' }
    }
    $norm = { param($v) (([string]$v).Trim() -replace '\s+', ' ').ToLowerInvariant() }
    $endpoint = ''
    if ($null -ne $Finding.PSObject.Properties['Endpoint']) { $endpoint = & $norm $Finding.Endpoint }
    return ('k1|{0}|{1}|{2}|{3}|{4}' -f [string]$Finding.Category, [string]$Finding.StatusCode, $rule, (& $norm $Finding.Target), $endpoint)
}

function Set-MspkiFindingKey {
    <#
    .SYNOPSIS
    Gives every finding a deterministic Key ("k1-" and 20 hex characters of the SHA-256 of its identity). Two findings with the same identity
    in one run are told apart by their order (the second gets "#2" in its identity), which is the order the run produced them in.
    Returns how many keys were set. A finding that already has a Key keeps it.

    .DESCRIPTION
    Category, status code, rule and target name the check and its subject; the status is NOT part of the Key, so the same check that went
    from a warning to a failure keeps its Key and shows as changed when two runs are compared.
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Findings = @(), $Knowledge = $null)
    if ($null -eq $Knowledge) { try { $Knowledge = Get-MspkiDiagnosisKnowledge } catch { $Knowledge = $null } }
    $seen = @{}
    $n = 0
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        foreach ($f in @($Findings)) {
            if ($null -eq $f) { continue }
            $id = ''
            try { $id = Get-MspkiFindingIdentity -Finding $f -Knowledge $Knowledge } catch { $id = 'k1|' + [string]$f.Category + '|' + [string]$f.StatusCode + '||' + ([string]$f.Target).ToLowerInvariant() + '|' }
            if ($seen.ContainsKey($id)) { $seen[$id]++; $id = '{0}#{1}' -f $id, $seen[$id] } else { $seen[$id] = 1 }
            if ($null -ne $f.PSObject.Properties['Key'] -and $f.Key) { continue }
            $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($id))
            $hex = -join ($bytes[0..9] | ForEach-Object { $_.ToString('x2') })
            $f | Add-Member -NotePropertyName 'Key' -NotePropertyValue ('k1-' + $hex) -Force
            $n++
        }
    }
    finally { $sha.Dispose() }
    return $n
}
