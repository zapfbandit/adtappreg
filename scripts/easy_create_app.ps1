# This script is super fragile, it will just not work most of the time,
# it will also make you lose all you're work

Import-Module -Name $(Join-Path -Path $PSScriptRoot -ChildPath "config")

# consts
$connectionConfig = Get-Config

function Validate-AppName {
    param (
        $AppName
    )

    $AppName -ne $null
}

function Validate-AppVersion {
    param (
        $AppName
    )
    
    $AppName -ne $null
}

function Validate-AppFile {
    param (
        $AppFilePath
    )
    
    # TODO: do basic checks?!?
    $AppFilePath -ne $null
}

function Simplify-AppName {
    param (
        $AppName
    )
    
    $AppName -replace '[^a-zA-Z0-9]','-'
}

function Create-AppInfoContent {
    param (
        $TemplateContent,
        $AppName,
        $AppVersion,
        $SimpleAppName,
        $InstallerPath,
        $Assignments
    )
    
    $output = $TemplateContent
    
    $output = $output.replace('${app_name}', $AppName)
    $output = $output.replace('${description}', $AppName)
    $output = $output.replace('${app_version}', $AppVersion)
    $output = $output.replace('${setup_file}', $(Split-Path $InstallerPath -leaf))
    $output = $output.replace('${remote_files_path}', "$SimpleAppName/$AppVersion/setup_files")
    $output = $output.replace('${install_type}', "msi:")
    
    $ass = "    "
    foreach ($a in $Assignments)
    {
        $ass += "`n    - $a"
    }
    $output = $output.replace('${assignments}', $ass)
    
    $output
}

$rootDir = Join-Path -Path $PSScriptRoot -ChildPath ".."

pushd $rootDir

& git checkout main
& git pull

# Get simple app info
$appName = $null
while ($(Validate-AppName $appName) -ne $true)
{
    $appName = Read-Host "Enter application name"
}

$appVersion = $null
while ($(Validate-AppVersion $appVersion) -ne $true)
{
    $appVersion = Read-Host "Enter application version (default: 1.0.0.0)"
    
    if ($appVersion -eq "")
    {
        $appVersion = "1.0.0.0"
    }
}

$appFile = $null
while ($(Validate-AppFile $appFile) -ne $true)
{
    $appFile = Read-Host "Enter local path to installer"
}

$assignments = @()
$ass = ""
while ($ass -ne $null)
{
    $ass = Read-Host "Enter assignments (One per line - valid values are: TestGroup. Empty value to finish.)"
    if ($ass -ne "")
    {
        $assignments += $ass
    }
    else
    {
        $ass = $null
    }
}

# Make app info
$simpleAppName = Simplify-AppName $appName
$appNameVer = "$($simpleAppName)_$appVersion"
Write-Host "$appName"
Write-Host "$simpleAppName"
Write-Host "$appNameVer"
& git checkout -b $appNameVer
New-Item -Path $(Join-Path -Path $rootDir -ChildPath "apps") -Name $simpleAppName -ItemType "directory"
New-Item -Path $(Join-Path -Path "$rootDir\apps" -ChildPath $simpleAppName) -Name $appVersion -ItemType "directory"
$appDir = Join-Path -Path "$rootDir\apps\$simpleAppName" -ChildPath $appVersion
$remoteDir = "$simpleAppName/$appVersion/setup_files"
$templateContents = Get-Content -Path $(Join-Path -Path $rootDir -ChildPath "scripts\info.template.yml")
$infoContents = Create-AppInfoContent $templateContents $appName $appVersion $simpleAppName $appFile $assignments
$infoContents | Out-File -FilePath $(Join-Path -Path $appDir -ChildPath "info.yml") -Encoding ASCII

# Upload installer
Write-Host
Write-Host "Uploading installer..." -ForegroundColor Yellow
$azcopyExe = Join-Path -Path $PSScriptRoot -ChildPath "azcopy.exe"
& $azcopyExe login status
if ($LastExitCode -ne 0)
{
    Write-Host
    Write-Host "Wake up! The instructions below require user interaction..." -ForegroundColor Yellow
    & $azcopyExe login
}
& $azcopyExe copy $appFile "https://$($connectionConfig.storageAccount).blob.core.windows.net/$($connectionConfig.containerName)/$remoteDir/$(Split-Path $appFile -leaf)"

# Hack up apply changes script
$changes = @"
Import-Module -Name `$(Join-Path -Path `$PSScriptRoot -ChildPath "upload_app")

`$localSetupFiles = `$null
`$config = "..\apps\$simpleAppName\$appVersion\info.yml"

Add-Application `$localSetupFiles `$config
"@
Set-Content -Path $(Join-Path -Path $rootDir -ChildPath "scripts\apply_change.ps1") -Value $changes -Encoding ASCII

# Commit and create pull request?!?
Write-Host
Write-Host "Creating pull request..." -ForegroundColor Yellow
& git add $rootDir
& git commit -m "Adding $simpleAppName"
& git push --set-upstream origin $appNameVer
$ghExe = Join-Path -Path $PSScriptRoot -ChildPath "gh.exe"
& $ghExe auth status
if ($LastExitCode -ne 0)
{
    Write-Host
    Write-Host "Wake up! The instructions below require user interaction..." -ForegroundColor Yellow
    & $ghExe auth login
}
& $ghExe pr create --title $simpleAppName --body "Please respond" --head $appNameVer

# Done/cleanup
& git checkout main
& git branch -D $appNameVer
Remove-Item -Path $(Join-Path -Path "$rootDir\apps" -CHildPath $simpleAppName) -Recurse

popd