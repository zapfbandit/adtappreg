Import-Module -Name $(Join-Path -Path $PSScriptRoot -ChildPath "upload_app")

$localSetupFiles = $null
$config = "..\apps\7-zip\21.7.0.0\info.yml"

Add-Application $localSetupFiles $config
