Import-Module -Name $(Join-Path -Path $PSScriptRoot -ChildPath "upload_app")

$localSetupFiles = $null
$remoteSetupFiles = @("winzip/1.0.0.0/setup_files")
$setupFilename = 'winzip260-64.msi'

$intuneInfo = Create-Intunewin $localSetupFiles $remoteSetupFiles $setupFilename

Write-Warning $intuneInfo.detectionXml
Write-Warning $intuneInfo.intuneWinFile
Write-Warning $intuneInfo.fileSize
