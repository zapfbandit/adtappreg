Import-Module -Name $(Join-Path -Path $PSScriptRoot -ChildPath "upload_app")

$localSetupFiles = $null
$config = "..\apps\python-3\1.0.0.0\info.yml"

Add-Application $localSetupFiles $config
