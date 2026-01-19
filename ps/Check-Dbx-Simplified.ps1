# From https://gist.github.com/out0xb2/f8e0bae94214889a89ac67fceb37f8c0#file-check-dbx-ps1
# Modified by github.com/cjee21

 $patchfile  = $args[0]

 if ($patchfile -eq  $null) {
   Write-Host "Patchfile not specified!`n"
   Break
 }
 $patchfile = (gci -literalpath $patchfile).FullName

 Import-Module -Force "$PSScriptRoot\Get-UEFIDatabaseSignatures.ps1"

 $DbxRaw = Get-SecureBootUEFI dbx
 $DbxFound = $DbxRaw | Get-UEFIDatabaseSignatures

 $DbxBytesRequired = [IO.File]::ReadAllBytes($patchfile)
 $DbxRequired = Get-UEFIDatabaseSignatures -BytesIn $DbxBytesRequired

 # Flatten into an array of required EfiSignatureData data objects
 $RequiredArray = foreach ($EfiSignatureList in $DbxRequired) {
     Write-Verbose $EfiSignatureList
     foreach ($RequiredSignatureData in $EfiSignatureList.SignatureList) {
         Write-Verbose  $RequiredSignatureData
         $RequiredSignatureData.SignatureData
     }
 }
 Write-Information "Required `n $RequiredArray"

 # Flatten into an array of EfiSignatureData data objects (read from dbx)
 $FoundArray = foreach ($EfiSignatureList in $DbxFound) {
     Write-Verbose $EfiSignatureList
     foreach ($FoundSignatureData in $EfiSignatureList.SignatureList) {
         Write-Verbose  $FoundSignatureData
         $FoundSignatureData.SignatureData
     }
 }
 Write-Information "Found `n $FoundArray"

 $successes = 0
 $failures = 0
 $requiredCount = $RequiredArray.Count
 foreach ($RequiredSig in $RequiredArray) {
    if ($FoundArray -contains $RequiredSig) {
        Write-Information "FOUND: $RequiredSig"
        $successes++
    } else {
        Write-Information "!!! NOT FOUND`n$RequiredSig`n!!!`n"
        $failures++
    }
    $i = $successes + $failures
    Write-Progress -Activity 'Checking if all patches applied' -Status "Checking element $i of $requiredCount" -PercentComplete ($i/$requiredCount *100)
 }

 if ($failures -ne 0) {
     Write-Host "FAIL: $failures failures, $successes successes detected" -ForegroundColor Red
     # $DbxRaw.Bytes | sc -encoding Byte dbx_found.bin
 } elseif ($successes -ne $RequiredArray.Count) {
     Write-Error "!!! Unexpected: $successes != $requiredCount expected successes!"
 } elseif ($successes -eq 0) {
     Write-Error "!!! Unexpected failure:  no successes detected, check command-line usage."
 } else {
     Write-Host "SUCCESS: $successes successes detected" -ForegroundColor Green
 }
