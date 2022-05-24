Import-Module -Name $(Join-Path -Path $PSScriptRoot -ChildPath "upload_app")

$localSetupFiles = $null
$config = "..\apps\7z\1.0.0.0\info.yml"

Add-Application $localSetupFiles $config
