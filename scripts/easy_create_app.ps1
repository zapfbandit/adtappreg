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
    
    # TODO: replace tokens
    
    $output
}

$rootDir = Join-Path -Path $PSScriptRoot -ChildPath ".."

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
$azcopyExe = Join-Path -Path $PSScriptRoot -ChildPath "azcopy.exe"
& $azcopyExe login status
if ($LastExitCode -ne 0)
{
    Write-Host
    Write-Host "Wake up! The instructions below require user interaction..." -ForegroundColor Yellow
    & $azcopyExe login
}
& $azcopyExe copy $appFile "https://$($connectionConfig.storageAccount).blob.core.windows.net/$($connectionConfig.containerName)/$remoteDir/$(Split-Path $appFile -leaf)"

# Commit and create pull request?!?


# Done/cleanup
& git checkout main
& git branch -d $appNameVer
Remove-Item -Path $(Join-Path -Path "$rootDir\apps" -CHildPath $simpleAppName) -Recurse
