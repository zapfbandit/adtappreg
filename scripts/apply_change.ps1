Import-Module -Name $(Join-Path -Path $PSScriptRoot -ChildPath "upload_app")

$localSetupFiles = $null#"..\apps\test\setup_files"
$config = Join-Path -Path $PSScriptRoot -ChildPath "..\apps\cmake\1.0.0.0\info.yml"

Add-Application $localSetupFiles $config