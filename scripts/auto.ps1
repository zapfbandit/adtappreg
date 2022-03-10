pushd $PSScriptRoot

& git checkout main
& git pull
powershell -ExecutionPolicy Bypass -File $(Join-Path -Path $PSScriptRoot -ChildPath "apply_change.ps1")

popd