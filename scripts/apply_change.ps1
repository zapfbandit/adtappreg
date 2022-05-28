Import-Module -Name $(Join-Path -Path $PSScriptRoot -ChildPath "upload_app")

$localSetupFiles = $null
$config = "..\apps\bob\1\info.yml"

Add-Application $localSetupFiles $config
