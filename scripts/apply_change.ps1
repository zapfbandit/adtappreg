Import-Module -Name $(Join-Path -Path $PSScriptRoot -ChildPath "upload_app")

$localSetupFiles = $null
$config = "..\apps\igor\1.0.0.1\info.yml"

Add-Application $localSetupFiles $config
