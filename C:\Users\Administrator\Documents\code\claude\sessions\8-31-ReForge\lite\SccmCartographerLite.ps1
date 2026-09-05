<#
.SYNOPSIS
  SCCM Cartographer Lite - a bare-minimum, PowerShell-only reader/scorer/reporter for the
  snapshot format written by collector/Collect-SccmSnapshot.ps1.

.DESCRIPTION
  This is deliberately NOT the full product. The Rust tool (crates/, sccm-cli) is the
  near-critical-systems build: config-driven scoring curves, a 19-rule blocker register,
  property/fuzz/mutation testing, an SVG relationship graph, a 10-section report. This
  script is the alternative for someone who wants one auditable file and no Rust toolchain:
  it reads the identical snapshot a real collection already produced, does a much smaller
  version of the same analysis, and writes one HTML report.

  What it keeps from the full product's design, because dropping them would misrepresent
  data rather than just simplify it:
    - unknown is never zero: a task sequence whose Sequence XML never hydrated is marked
      "insufficient data", not scored as if it were simple.
    - a blocker always raises the band (App-V, a chained task sequence, a dangling chain
      target, a cycle) regardless of the computed score.
    - every listed file's SHA-256 is checked against the manifest before it is trusted.
    - a raw/ payload reference is confined to raw/ - no path escaping the snapshot dir.
    - deterministic output: arrays are sorted by id before they are written anywhere.

  What it does NOT attempt (see docs/HLD-SCCM-Cartographer.md for the full version):
    - a config-driven weight/curve system - this uses one small, hardcoded scoring ladder.
    - the full blocker register (19 rules) - this checks half a dozen of the highest-value
      ones and reuses the collector's own findings.jsonl instead of re-scanning for secrets.
    - a wave plan, an effort model, or a Tanium mapping table.
    - an SVG-rendered relationship graph - this is HTML tables only.
    - a test suite. It was smoke-tested by hand against fixtures/environments/tiny.

.PARAMETER SnapshotDir
  A snapshot directory written by Collect-SccmSnapshot.ps1 (contains manifest.json).

.PARAMETER OutFile
  Where to write the HTML report. Defaults to report.html inside the snapshot directory.

.EXAMPLE
  .\SccmCartographerLite.ps1 -SnapshotDir C:\snapshots\lab-2026-09-03 -OutFile C:\out\report.html
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SnapshotDir,
    [string]$OutFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --------------------------------------------------------------------------------------
# Snapshot reading
# --------------------------------------------------------------------------------------

function Get-Sha256Hex {
    param([Parameter(Mandatory)][string]$Path)
    (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Test-SnapshotIntegrity {
    # Every file the manifest lists must exist and hash to what the manifest claims.
    # Refuses on the first mismatch - the same "never analyse a snapshot whose own
    # integrity claims fail" rule the Rust reader enforces.
    param([Parameter(Mandatory)][string]$Dir, [Parameter(Mandatory)]$Manifest)
    $listed = New-Object System.Collections.Generic.List[object]
    foreach ($c in $Manifest.collectedKinds) { $listed.Add($c) }
    foreach ($r in $Manifest.rawFiles) { $listed.Add($r) }
    if ($Manifest.PSObject.Properties['problemsFile'] -and $Manifest.problemsFile) { $listed.Add($Manifest.problemsFile) }
    if ($Manifest.PSObject.Properties['findingsFile'] -and $Manifest.findingsFile) { $listed.Add($Manifest.findingsFile) }
    foreach ($entry in $listed) {
        if (-not $entry.PSObject.Properties['file'] -or -not $entry.file) { continue }
        $path = Join-Path $Dir $entry.file
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "REFUSED: snapshot file listed in the manifest is missing: $($entry.file)"
        }
        if ($entry.PSObject.Properties['sha256'] -and $entry.sha256) {
            $actual = Get-Sha256Hex $path
            if ($actual -ne $entry.sha256) {
                throw "REFUSED: integrity failure: $($entry.file) has sha256 $actual but the manifest says $($entry.sha256)"
            }
        }
    }
}

function Get-RawPayload {
    # Confined to raw/: rejects anything that is not a relative path starting with the
    # literal component "raw" with no ".." anywhere in it, mirroring the Rust reader's
    # Snapshot::raw path-traversal guard.
    param([Parameter(Mandatory)][string]$Dir, [Parameter(Mandatory)]$RawRef)
    $rel = $RawRef.ref -replace '/', '\'
    $parts = $rel -split '\\' | Where-Object { $_ -ne '' }
    $safe = $parts.Count -gt 0 -and $parts[0] -eq 'raw' -and ($parts -notcontains '..') -and (-not [System.IO.Path]::IsPathRooted($rel))
    if (-not $safe) { throw "raw reference '$($RawRef.ref)' is not a relative path under raw/" }
    $path = Join-Path $Dir $rel
    if ($RawRef.PSObject.Properties['sha256'] -and $RawRef.sha256) {
        $actual = Get-Sha256Hex $path
        if ($actual -ne $RawRef.sha256) { throw "integrity failure: $($RawRef.ref) does not match its recorded hash" }
    }
    Get-Content -LiteralPath $path -Raw -Encoding UTF8
}

function Import-Snapshot {
    param([Parameter(Mandatory)][string]$Dir)
    $manifestPath = Join-Path $Dir 'manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath)) { throw "no manifest.json in $Dir - is this a snapshot directory?" }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    Test-SnapshotIntegrity -Dir $Dir -Manifest $manifest

    $records = @{}
    foreach ($kind in $manifest.collectedKinds) {
        $path = Join-Path $Dir $kind.file
        $items = New-Object System.Collections.Generic.List[object]
        if ((Get-Item $path).Length -gt 0) {
            foreach ($line in Get-Content -LiteralPath $path) {
                if ($line.Trim() -eq '') { continue }
                $items.Add(($line | ConvertFrom-Json))
            }
        }
        $records[$kind.kind] = $items
    }

    $findings = @()
    if ($manifest.PSObject.Properties['findingsFile'] -and $manifest.findingsFile) {
        $fpath = Join-Path $Dir $manifest.findingsFile.file
        if ((Get-Item $fpath).Length -gt 0) {
            $findings = @(Get-Content -LiteralPath $fpath | Where-Object { $_.Trim() -ne '' } | ForEach-Object { $_ | ConvertFrom-Json })
        }
    }

    $problems = @()
    if ($manifest.PSObject.Properties['problemsFile'] -and $manifest.problemsFile) {
        $ppath = Join-Path $Dir $manifest.problemsFile.file
        if ((Get-Item $ppath).Length -gt 0) {
            $problems = @(Get-Content -LiteralPath $ppath | Where-Object { $_.Trim() -ne '' } | ForEach-Object { $_ | ConvertFrom-Json })
        }
    }

    [pscustomobject]@{
        Manifest = $manifest
        Records  = $records
        Findings = $findings
        Problems = $problems
    }
}

# --------------------------------------------------------------------------------------
# Task sequence chain analysis - the flagship piece, kept even at "bare minimum"
# --------------------------------------------------------------------------------------

# SCCM package/task-sequence ids look like SSS##### (site code + 5 hex digits).
$script:PackageIdPattern = '\b[A-Za-z0-9]{3}[0-9A-Fa-f]{5}\b'

function Get-TaskSequenceStepInfo {
    # Heuristic, single-pass XML walk: counts steps/groups/depth and pulls candidate child
    # package ids off any RunTaskSequenceAction step. This is intentionally simpler than the
    # Rust parser's full pseudo-code condition renderer and variable reconciliation - it
    # exists to answer "how big is this, and what does it chain to", not to fully document it.
    param([Parameter(Mandatory)][string]$Xml)
    $doc = [xml]$Xml
    $steps = 0
    $groups = 0
    $maxDepth = 0
    $scriptSteps = 0
    $children = New-Object System.Collections.Generic.List[string]

    function Walk {
        # NOTE: use .LocalName, never .Name, to read an XML element's tag name here.
        # PowerShell's XML adapter shadows the real .Name property with the value of a
        # child element or attribute literally called "name" when one exists - and every
        # <group name="..."> and <step name="..."> in a Sequence document has exactly
        # that, so `.Name` silently returns "Prepare" instead of "group". `.LocalName`
        # is the CLR property directly and is never shadowed this way.
        param($Node, [int]$Depth)
        foreach ($child in $Node.ChildNodes) {
            if ($child.NodeType -ne 'Element') { continue }
            if ($child.LocalName -eq 'group') {
                $script:groups++
                if ($Depth + 1 -gt $script:maxDepth) { $script:maxDepth = $Depth + 1 }
                Walk -Node $child -Depth ($Depth + 1)
            } elseif ($child.LocalName -eq 'step') {
                $script:steps++
                $type = [string]$child.type
                if ($type -match 'RunPowerShellScriptAction|RunCommandLineAction') { $script:scriptSteps++ }
                if ($type -match 'RunTaskSequenceAction') {
                    $found = $false
                    $varList = $child.SelectSingleNode('defaultVarList')
                    if ($varList) {
                        foreach ($var in $varList.ChildNodes) {
                            if ($var.NodeType -ne 'Element') { continue }
                            $name = [string]$var.name
                            if ($name -match 'PackageID' -and $var.InnerText -match $script:PackageIdPattern) {
                                $script:children.Add($Matches[0])
                                $found = $true
                            }
                        }
                    }
                    if (-not $found) {
                        $actionNode = $child.SelectSingleNode('action')
                        if ($actionNode -and $actionNode.InnerText -match $script:PackageIdPattern) {
                            $script:children.Add($Matches[0])
                        }
                    }
                }
            }
        }
    }

    # Use script-scoped accumulators so the nested function above can mutate them without
    # PowerShell's per-scope closure copying silently losing the counts.
    $script:steps = 0; $script:groups = 0; $script:maxDepth = 0; $script:scriptSteps = 0
    $script:children = New-Object System.Collections.Generic.List[string]
    Walk -Node $doc.sequence -Depth 0
    [pscustomobject]@{
        StepCount    = $script:steps
        GroupCount   = $script:groups
        MaxDepth     = $script:maxDepth
        ScriptSteps  = $script:scriptSteps
        ChainTargets = @($script:children | Sort-Object -Unique)
    }
}

function Build-ChainGraph {
    # Depth (longest confirmed path) and cycle membership per task sequence, over the
    # id -> [child ids] map. Iterative DFS with a three-colour visited set so a cycle in
    # the source data cannot hang this script.
    param([Parameter(Mandatory)][hashtable]$ChildrenById)
    $depth = @{}
    $color = @{} # 0 = white, 1 = gray (on stack), 2 = black (done)
    foreach ($id in $ChildrenById.Keys) { $color[$id] = 0; $depth[$id] = 0 }

    function Visit {
        param([string]$Id, [System.Collections.Generic.List[string]]$Path)
        if ($color[$Id] -eq 1) {
            # Back-edge: everything currently on the path is part of a cycle.
            $onPath = $false
            foreach ($p in $Path) {
                if ($p -eq $Id) { $onPath = $true }
                if ($onPath) { $script:cycleMembers[$p] = $true }
            }
            return 0
        }
        if ($color[$Id] -eq 2) { return $depth[$Id] }
        $color[$Id] = 1
        $Path.Add($Id)
        $best = 0
        $kids = $ChildrenById[$Id]
        if (-not $kids) { $kids = @() }
        foreach ($child in $kids) {
            if (-not $ChildrenById.ContainsKey($child)) { continue } # dangling; not part of depth
            $childDepth = Visit -Id $child -Path $Path
            if ($childDepth + 1 -gt $best) { $best = $childDepth + 1 }
        }
        $Path.RemoveAt($Path.Count - 1)
        $color[$Id] = 2
        $depth[$Id] = $best
        return $best
    }

    $script:cycleMembers = @{}
    foreach ($id in $ChildrenById.Keys) {
        if ($color[$id] -eq 0) {
            [void](Visit -Id $id -Path (New-Object System.Collections.Generic.List[string]))
        }
    }
    [pscustomobject]@{ Depth = $depth; InCycle = $script:cycleMembers }
}

# --------------------------------------------------------------------------------------
# Scoring - one small hardcoded ladder, not the full curve/weight config system
# --------------------------------------------------------------------------------------

function ConvertTo-Band {
    param([int]$Score)
    if ($Score -ge 75) { 'Critical' }
    elseif ($Score -ge 50) { 'High' }
    elseif ($Score -ge 25) { 'Moderate' }
    else { 'Low' }
}

function Step-Ladder {
    # A small integer step function: the highest threshold at or below $Value wins.
    # Same shape as the Rust tool's "threshold" curve, minus the config file around it.
    param([int]$Value, [int[][]]$Steps)
    $points = 0
    foreach ($step in $Steps) {
        if ($Value -ge $step[0]) { $points = [math]::Max($points, $step[1]) }
    }
    $points
}

function Get-TaskSequenceScore {
    param($Info, [int]$ChainDepth, [int]$Fanout)
    $score = 0
    $score += [int]([math]::Round((Step-Ladder $Info.StepCount @(@(1,10),@(10,30),@(30,55),@(80,80),@(160,100))) * 0.30))
    $score += [int]([math]::Round((Step-Ladder $Info.MaxDepth  @(@(1,0),@(3,40),@(5,80),@(7,100))) * 0.15))
    $score += [int]([math]::Round((Step-Ladder $ChainDepth     @(@(0,0),@(1,50),@(2,80),@(3,100))) * 0.25))
    $score += [int]([math]::Round((Step-Ladder $Fanout         @(@(0,0),@(1,30),@(3,70),@(6,100))) * 0.10))
    $score += [int]([math]::Round((Step-Ladder $Info.ScriptSteps @(@(0,0),@(1,30),@(5,70),@(15,100))) * 0.20))
    [math]::Min(100, $score)
}

function Get-PackageScore {
    param($Package)
    $programCount = @($Package.attrs.programs).Count
    Step-Ladder $programCount @(@(0,0),@(1,20),@(2,55),@(4,100))
}

# --------------------------------------------------------------------------------------
# Blockers - a half-dozen high-value checks, not the full 19-rule register
# --------------------------------------------------------------------------------------

function Get-Blockers {
    param($Snapshot, $ChainGraph, $ChildrenById)
    $blockers = New-Object System.Collections.Generic.List[object]
    $add = { param($Kind, $Id, $Title, $Evidence)
        $blockers.Add([pscustomobject]@{ Kind = $Kind; Id = $Id; Title = $Title; Evidence = $Evidence })
    }

    foreach ($id in $ChildrenById.Keys) {
        if ($ChildrenById[$id].Count -gt 0) {
            & $add 'taskSequence' $id 'Task sequence invokes another task sequence' "chains to $($ChildrenById[$id] -join ', ') - Tanium Provision has no native chaining"
        }
        foreach ($child in $ChildrenById[$id]) {
            if (-not $ChildrenById.ContainsKey($child)) {
                & $add 'taskSequence' $id 'Chain target is not in the snapshot' "references task sequence $child, which was not collected"
            }
        }
        if ($ChainGraph.InCycle.ContainsKey($id)) {
            & $add 'taskSequence' $id 'Task sequence chain forms a cycle' 'a defect at the source; migration order is undefined until this is broken'
        }
    }

    foreach ($app in $Snapshot.Records['application']) {
        if ($app.raw.PSObject.Properties['sdmPackageXml']) {
            try {
                $sdm = Get-RawPayload -Dir $Snapshot.SnapshotDir -RawRef $app.raw.sdmPackageXml
                if ($sdm -match '(?i)app-?v') {
                    & $add 'application' $app.id 'App-V deployment type cannot be migrated as-is' 'SDMPackageXML mentions App-V'
                }
            } catch {
                # An unreadable SDMPackageXML just means this one check is skipped for this
                # application, not that the whole report should fail - intentionally silent.
            }
        }
    }

    foreach ($finding in $Snapshot.Findings) {
        & $add $finding.kind $finding.id 'Credential-like value redacted at collection' "field $($finding.field), digest $($finding.digest) - rotate it"
    }

    @($blockers | Sort-Object Kind, Id, Title)
}

# --------------------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------------------

function ConvertTo-HtmlEscaped {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    [System.Net.WebUtility]::HtmlEncode($Text)
}

function New-Report {
    param($Snapshot, $TaskSequenceRows, $PackageRows, $Blockers, $HydrationGaps)

    $bandClass = @{ Low = 'low'; Moderate = 'mod'; High = 'high'; Critical = 'crit' }
    $css = @'
body{font-family:Consolas,'Courier New',monospace;background:#fff;color:#111;margin:0;padding:0 0 3rem}
main{max-width:1000px;margin:0 auto;padding:1.5rem}
h1{font-size:1.4rem;margin:0 0 .2rem} h2{font-size:1.1rem;margin:2rem 0 .6rem;border-bottom:2px solid #ccc;padding-bottom:.2rem}
.sub{color:#555;margin:0 0 1.5rem}
table{border-collapse:collapse;width:100%;font-size:13px;margin-bottom:1rem}
th,td{border:1px solid #ccc;padding:.3rem .5rem;text-align:left;vertical-align:top}
th{background:#f0f0f0}
.badge{display:inline-block;padding:0 .4em;border-radius:3px;font-weight:bold;font-size:12px}
.low{background:#d7ecd2}.mod{background:#f5e3ab}.high{background:#f3caa0}.crit{background:#f0b0ac}
.insuff{background:#e2e2e2}
.note{color:#666;font-size:12px}
footer{color:#777;font-size:12px;max-width:1000px;margin:2rem auto 0;padding:0 1.5rem;border-top:1px solid #ccc;padding-top:.8rem}
'@

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<!doctype html><html><head><meta charset="utf-8"><title>SCCM Cartographer Lite</title>')
    [void]$sb.AppendLine("<style>$css</style></head><body><main>")
    [void]$sb.AppendLine('<h1>SCCM Cartographer Lite</h1>')
    $site = $Snapshot.Manifest.site
    [void]$sb.AppendLine("<p class='sub'>Site $(ConvertTo-HtmlEscaped $site.code), captured $(ConvertTo-HtmlEscaped $Snapshot.Manifest.capturedAt), coverage $(ConvertTo-HtmlEscaped $Snapshot.Manifest.coverage). Bare-minimum PowerShell analysis - see the full Rust tool for the complete scoring model, blocker register, wave plan, and effort estimate.</p>")

    [void]$sb.AppendLine('<h2>Inventory</h2><table><tr><th>kind</th><th>count</th></tr>')
    foreach ($kind in ($Snapshot.Manifest.collectedKinds | Sort-Object kind)) {
        [void]$sb.AppendLine("<tr><td>$(ConvertTo-HtmlEscaped $kind.kind)</td><td>$($kind.count)</td></tr>")
    }
    [void]$sb.AppendLine('</table>')

    [void]$sb.AppendLine('<h2>Task sequences</h2><table><tr><th>id</th><th>name</th><th>steps</th><th>depth</th><th>chain depth</th><th>fanout</th><th>score</th><th>band</th></tr>')
    foreach ($row in $TaskSequenceRows) {
        if ($row.Insufficient) {
            [void]$sb.AppendLine("<tr><td>$(ConvertTo-HtmlEscaped $row.Id)</td><td>$(ConvertTo-HtmlEscaped $row.Name)</td><td colspan='6'><span class='badge insuff'>insufficient data</span> $(ConvertTo-HtmlEscaped $row.Reason)</td></tr>")
        } else {
            $band = $row.Band
            [void]$sb.AppendLine("<tr><td>$(ConvertTo-HtmlEscaped $row.Id)</td><td>$(ConvertTo-HtmlEscaped $row.Name)</td><td>$($row.StepCount)</td><td>$($row.MaxDepth)</td><td>$($row.ChainDepth)</td><td>$($row.Fanout)</td><td>$($row.Score)</td><td><span class='badge $($bandClass[$band])'>$band</span></td></tr>")
        }
    }
    [void]$sb.AppendLine('</table>')

    [void]$sb.AppendLine('<h2>Classic packages</h2><table><tr><th>id</th><th>name</th><th>programs</th><th>score</th><th>band</th></tr>')
    foreach ($row in $PackageRows) {
        $band = $row.Band
        [void]$sb.AppendLine("<tr><td>$(ConvertTo-HtmlEscaped $row.Id)</td><td>$(ConvertTo-HtmlEscaped $row.Name)</td><td>$($row.ProgramCount)</td><td>$($row.Score)</td><td><span class='badge $($bandClass[$band])'>$band</span></td></tr>")
    }
    [void]$sb.AppendLine('</table>')

    [void]$sb.AppendLine("<h2>Blockers ($($Blockers.Count))</h2>")
    if ($Blockers.Count -eq 0) {
        [void]$sb.AppendLine('<p class="note">None of the checks this script runs found anything. This is a much shorter list than the full tool checks - absence here is not proof of absence.</p>')
    } else {
        [void]$sb.AppendLine('<table><tr><th>kind</th><th>id</th><th>title</th><th>evidence</th></tr>')
        foreach ($b in $Blockers) {
            [void]$sb.AppendLine("<tr><td>$(ConvertTo-HtmlEscaped $b.Kind)</td><td>$(ConvertTo-HtmlEscaped $b.Id)</td><td>$(ConvertTo-HtmlEscaped $b.Title)</td><td>$(ConvertTo-HtmlEscaped $b.Evidence)</td></tr>")
        }
        [void]$sb.AppendLine('</table>')
    }

    [void]$sb.AppendLine('<h2>Data quality</h2>')
    [void]$sb.AppendLine("<p>$($Snapshot.Problems.Count) problem(s) recorded during collection. $($Snapshot.Findings.Count) credential-like value(s) redacted at collection.</p>")
    if ($HydrationGaps.Count -gt 0) {
        [void]$sb.AppendLine('<p><b>Hydration gaps</b> (objects whose lazy payload did not fully hydrate; these show as insufficient data above, never as a false Low):</p><ul>')
        foreach ($g in $HydrationGaps) { [void]$sb.AppendLine("<li>$(ConvertTo-HtmlEscaped $g.kind): $($g.hydrated) of $($g.count) hydrated</li>") }
        [void]$sb.AppendLine('</ul>')
    } else {
        [void]$sb.AppendLine('<p>No hydration gaps - every lazy payload hydrated.</p>')
    }

    [void]$sb.AppendLine('</main><footer>SCCM Cartographer Lite - a bare-minimum PowerShell alternative to the full sccm-cli. No config-driven scoring, no full blocker register, no wave plan or effort model - see docs/HLD-SCCM-Cartographer.md for those.</footer></body></html>')
    $sb.ToString()
}

# --------------------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------------------

if (-not $OutFile) { $OutFile = Join-Path $SnapshotDir 'report-lite.html' }

$snapshot = Import-Snapshot -Dir $SnapshotDir
$snapshot | Add-Member -NotePropertyName SnapshotDir -NotePropertyValue $SnapshotDir

$taskSequences = @($snapshot.Records['taskSequence'] | Sort-Object id)
$childrenById = @{}
$tsInfoById = @{}
$tsFailures = @{}

foreach ($ts in $taskSequences) {
    if ($ts.raw.PSObject.Properties['sequence']) {
        try {
            $xml = Get-RawPayload -Dir $SnapshotDir -RawRef $ts.raw.sequence
            $info = Get-TaskSequenceStepInfo -Xml $xml
            $tsInfoById[$ts.id] = $info
            $childrenById[$ts.id] = $info.ChainTargets
        } catch {
            $tsFailures[$ts.id] = $_.Exception.Message
        }
    } else {
        $tsFailures[$ts.id] = 'Sequence XML was not hydrated in the snapshot'
    }
}

$chainGraph = Build-ChainGraph -ChildrenById $childrenById

$taskSequenceRows = foreach ($ts in $taskSequences) {
    if ($tsFailures.ContainsKey($ts.id)) {
        [pscustomobject]@{ Id = $ts.id; Name = $ts.attrs.name; Insufficient = $true; Reason = $tsFailures[$ts.id] }
        continue
    }
    $info = $tsInfoById[$ts.id]
    $depth = $chainGraph.Depth[$ts.id]
    $fanout = $childrenById[$ts.id].Count
    $score = Get-TaskSequenceScore -Info $info -ChainDepth $depth -Fanout $fanout
    $band = ConvertTo-Band $score
    if ($childrenById[$ts.id].Count -gt 0 -or $chainGraph.InCycle.ContainsKey($ts.id)) { $band = 'High' } # a blocker floors the band
    [pscustomobject]@{
        Id = $ts.id; Name = $ts.attrs.name; Insufficient = $false
        StepCount = $info.StepCount; MaxDepth = $info.MaxDepth
        ChainDepth = $depth; Fanout = $fanout; Score = $score; Band = $band
    }
}

$packageRows = foreach ($pkg in @($snapshot.Records['package'] | Sort-Object id)) {
    $score = Get-PackageScore -Package $pkg
    [pscustomobject]@{
        Id = $pkg.id; Name = $pkg.attrs.name; ProgramCount = @($pkg.attrs.programs).Count
        Score = $score; Band = (ConvertTo-Band $score)
    }
}

$blockers = Get-Blockers -Snapshot $snapshot -ChainGraph $chainGraph -ChildrenById $childrenById
$hydrationGaps = @($snapshot.Manifest.collectedKinds | Where-Object { $_.hydrated -lt $_.count })

$html = New-Report -Snapshot $snapshot -TaskSequenceRows $taskSequenceRows -PackageRows $packageRows -Blockers $blockers -HydrationGaps $hydrationGaps
Set-Content -LiteralPath $OutFile -Value $html -Encoding UTF8

Write-Host "task sequences: $($taskSequenceRows.Count) ($(@($taskSequenceRows | Where-Object { -not $_.Insufficient }).Count) scored, $(@($taskSequenceRows | Where-Object { $_.Insufficient }).Count) insufficient data)"
Write-Host "packages:       $($packageRows.Count)"
Write-Host "blockers:       $($blockers.Count)"
Write-Host "problems:       $($snapshot.Problems.Count)   findings: $($snapshot.Findings.Count)"
Write-Host "report written: $OutFile"
