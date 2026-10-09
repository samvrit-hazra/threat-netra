<#
==============================================================================
 THREAT NETRA // CONTINUOUS LOG INGESTION AGENT (WINDOWS POWERSHELL)
 Enterprise Defense & Data-Intelligence Telemetry Forwarder v2.6
==============================================================================
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [string]$ApiUrl = "",

    [Parameter(Mandatory=$false)]
    [string]$LogFile = "",

    [Parameter(Mandatory=$false)]
    [string]$EventLogChannel = "",

    [Parameter(Mandatory=$false)]
    [int]$Interval = 10
)

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  THREAT NETRA // CONTINUOUS LOG INGESTION AGENT (WINDOWS)" -ForegroundColor White
Write-Host "  Sovereign Threat Forensics & Telemetry Forwarder v2.6" -ForegroundColor DarkGray
Write-Host "======================================================================" -ForegroundColor Cyan

# Step 1: Prompt for Secret API Ingestion URL if missing
if ([string]::IsNullOrWhiteSpace($ApiUrl)) {
    Write-Host ""
    Write-Host "[?] Enter Secret API Ingestion URL:" -ForegroundColor Yellow
    Write-Host "    (Obtain this from the 'Continuous Agent' tab in Threat Netra)" -ForegroundColor DarkGray
    $ApiUrl = Read-Host "URL"
}

$ApiUrl = $ApiUrl.Trim()
if ([string]::IsNullOrWhiteSpace($ApiUrl) -or -not ($ApiUrl -match "^https?://")) {
    Write-Host "[X] Error: Valid HTTP/HTTPS API URL required." -ForegroundColor Red
    exit 1
}

# Step 2: Choose Source (Event Log or File)
$Mode = "EventLog"
if ([string]::IsNullOrWhiteSpace($LogFile) -and [string]::IsNullOrWhiteSpace($EventLogChannel)) {
    Write-Host ""
    Write-Host "[?] Select Telemetry Source:" -ForegroundColor Yellow
    Write-Host "    [1] Windows Security Event Log (Security / EventID 4625, 4624, 4720, etc.)" -ForegroundColor White
    Write-Host "    [2] Windows System Event Log (System / EventID 7045, etc.)" -ForegroundColor White
    Write-Host "    [3] Custom Log File (IIS / Application .log / .txt)" -ForegroundColor White
    $Choice = Read-Host "Select option [1-3] (default 1)"
    if ([string]::IsNullOrWhiteSpace($Choice)) { $Choice = "1" }

    switch ($Choice) {
        "1" { $EventLogChannel = "Security" }
        "2" { $EventLogChannel = "System" }
        "3" {
            $LogFile = Read-Host "Enter log file path (e.g. C:\inetpub\logs\LogFiles\u_ex.log)"
            $Mode = "File"
        }
        default { $EventLogChannel = "Security" }
    }
} elseif (-not [string]::IsNullOrWhiteSpace($LogFile)) {
    $Mode = "File"
}

Write-Host ""
Write-Host "[+] Target Ingestion URL: $ApiUrl" -ForegroundColor Green
if ($Mode -eq "EventLog") {
    Write-Host "[+] Monitoring Event Channel: $EventLogChannel" -ForegroundColor Green
} else {
    Write-Host "[+] Monitoring File: $LogFile" -ForegroundColor Green
}
Write-Host "[+] Poll Interval: $Interval seconds" -ForegroundColor Green
Write-Host "[*] Press Ctrl+C at any time to terminate agent." -ForegroundColor DarkGray
Write-Host "----------------------------------------------------------------------" -ForegroundColor DarkGray

# Helper to send log text to API
function Send-LogBatch {
    param ([string]$RawText)
    if ([string]::IsNullOrWhiteSpace($RawText)) { return $null }

    try {
        $headers = @{ "Content-Type" = "text/plain; charset=utf-8" }
        $response = Invoke-RestMethod -Uri $ApiUrl -Method Post -Body $RawText -Headers $headers -TimeoutSec 15
        return $response
    } catch {
        Write-Host "[$((Get-Date).ToString('HH:mm:ss'))] [X] Upload failed: $_" -ForegroundColor Red
        return $null
    }
}

# -------------------------------------------------------------------------
# MODE A: WINDOWS EVENT LOG FORWARDING
# -------------------------------------------------------------------------
if ($Mode -eq "EventLog") {
    $LastRecordId = $null

    # Initial probe for newest record ID
    try {
        $initEvent = Get-WinEvent -LogName $EventLogChannel -MaxEvents 1 -ErrorAction Stop
        if ($initEvent) {
            $LastRecordId = $initEvent.RecordId
            Write-Host "[*] Synchronized with newest event record ID: $LastRecordId" -ForegroundColor Cyan
        }
    } catch {
        Write-Host "[!] Warning reading channel $EventLogChannel: $_" -ForegroundColor Yellow
        Write-Host "    Tip: Run PowerShell as Administrator to read Security event log." -ForegroundColor DarkGray
    }

    Write-Host "[●] Active Event Log Forwarding Started..." -ForegroundColor Green

    while ($true) {
        Start-Sleep -Seconds $Interval
        try {
            $filter = @{
                LogName = $EventLogChannel
            }
            # Fetch recent events
            $events = Get-WinEvent -FilterHashtable $filter -MaxEvents 50 -ErrorAction SilentlyContinue | Sort-Object RecordId

            $newEvents = @()
            if ($null -eq $LastRecordId) {
                $newEvents = $events
            } else {
                $newEvents = $events | Where-Object { $_.RecordId -gt $LastRecordId }
            }

            if ($newEvents.Count -gt 0) {
                $lines = @()
                foreach ($ev in $newEvents) {
                    $timestamp = $ev.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                    $computer = $ev.MachineName
                    $id = $ev.Id
                    $msg = ($ev.Message -replace "[\r\n]+", " ").Trim()
                    if ($msg.Length -gt 250) { $msg = $msg.Substring(0, 250) + "..." }
                    $line = "$timestamp $computer $EventLogChannel EventID: $id $msg"
                    $lines += $line
                    $LastRecordId = [Math]::Max($LastRecordId, $ev.RecordId)
                }

                $batchText = $lines -join "`n"
                $resp = Send-LogBatch -RawText $batchText
                if ($resp -and $resp.status -eq "success") {
                    $timeStr = (Get-Date).ToString("HH:mm:ss")
                    Write-Host "[$timeStr] [✓] Streamed $($lines.Count) events | Threat Level: $($resp.threat_level) (Score: $($resp.threat_score)/100, Hostiles: $($resp.hostile_ips))" -ForegroundColor Green
                }
            }
        } catch {
            Write-Host "[!] Query warning: $_" -ForegroundColor DarkGray
        }
    }
}

# -------------------------------------------------------------------------
# MODE B: FILE LOG FORWARDING
# -------------------------------------------------------------------------
if ($Mode -eq "File") {
    if (-not (Test-Path $LogFile)) {
        Write-Host "[X] Error: File '$LogFile' does not exist." -ForegroundColor Red
        exit 1
    }

    $lastLineCount = (Get-Content $LogFile | Measure-Object -Line).Lines
    Write-Host "[*] Starting at line $lastLineCount in $LogFile" -ForegroundColor Cyan
    Write-Host "[●] Active File Tailing Started..." -ForegroundColor Green

    while ($true) {
        Start-Sleep -Seconds $Interval
        if (-not (Test-Path $LogFile)) { continue }

        $currentLines = (Get-Content $LogFile | Measure-Object -Line).Lines
        if ($currentLines -lt $lastLineCount) {
            Write-Host "[*] File rotated. Resetting pointer." -ForegroundColor Yellow
            $lastLineCount = 0
        }

        if ($currentLines -gt $lastLineCount) {
            $linesToSkip = $lastLineCount
            $newLines = Get-Content $LogFile | Select-Object -Skip $linesToSkip
            $lineCount = $currentLines - $lastLineCount

            $batchText = $newLines -join "`n"
            $resp = Send-LogBatch -RawText $batchText
            if ($resp -and $resp.status -eq "success") {
                $timeStr = (Get-Date).ToString("HH:mm:ss")
                Write-Host "[$timeStr] [✓] Streamed $lineCount lines | Threat Level: $($resp.threat_level) (Score: $($resp.threat_score)/100)" -ForegroundColor Green
                $lastLineCount = $currentLines
            }
        }
    }
}
