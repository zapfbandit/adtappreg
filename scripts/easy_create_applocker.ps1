# This script is super fragile, it will just not work most of the time,
# it will also make you lose all you're work

. ./Common.ps1
. ./Applocker.ps1

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

function Validate-InstallAccount {
    param (
        $InstallAccount
    )
    
    if ($InstallAccount -eq $null)
    {
        return $false
    }
    
    ($InstallAccount.Trim() -match '^user$') -or ($InstallAccount.Trim() -match '^system$')
}

function Create-AppInfoContent {
    param (
        $TemplateContent,
        $AppName,
        $AppVersion,
        $SimpleAppName,
        $InstallerPath,
        $Assignments,
        $InstallAccount
    )
    
    $output = $TemplateContent
    
    $output = $output.replace('${app_name}', $AppName)
    $output = $output.replace('${description}', $AppName)
    $output = $output.replace('${app_version}', $AppVersion)
    $output = $output.replace('${setup_file}', $(Split-Path $InstallerPath -leaf))
    $output = $output.replace('${remote_files_path}', "$SimpleAppName/$AppVersion/setup_files")
    $output = $output.replace('${install_type}', "msi:")
    $output = $output.replace('${install_account}', $InstallAccount)
    
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


# Make app info
$simpleAppName = Simplify-AppName $appName
$appNameVer = "$($simpleAppName)_$appVersion"
$appDir = Join-Path -Path "$rootDir\apps\$simpleAppName" -ChildPath $appVersion
$remoteDir = "$simpleAppName/$appVersion/setup_files"

& git remote prune origin
$branchList = & git branch -r
$branchFound = ($branchList -match $appNameVer)

if ($branchFound -ne "")
{
   echo ""
   echo "The application creation request for `"$appNameVer`" has been requested but not yet approved."
   echo "Harrass your IT administrator ;-)"
   echo ""
   pause
   exit 1
}

$folderFound = Test-Path $appDir

if ($folderFound -eq $False)
{
   echo ""
   echo "The application `"$appNameVer`" was not found in main."
   echo "Please run `"easy_create_app.ps1`" before this command."
   echo ""
   pause
   exit 1
}

& git checkout -b $appNameVer

$installedDir = $null
while ($(Validate-AppFile $installedDir) -ne $true)
{
    $installedDir = Read-Host "Enter local path to the installed directory"
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

# install account
$installAccount = 'system'
# NOTE: installing as user doesn't work at the moment
#$installAccount = $null
#while ($(Validate-InstallAccount $installAccount) -ne $true)
#{
#    $installAccount = Read-Host "Enter install account (Valid values: user, system)"
#}

CreateAppLockerPolicy $sid "$appDir/applocker.xml" $installedDir

GetPackages
LoginAsSubscription
LocateStorage

UploadFile "$appDir/applocker.xml" $remoteDir

# Commit and create pull request?!?
Write-Host
Write-Host "Creating pull request..." -ForegroundColor Yellow
& git pull
& git add $rootDir
& git commit -m "Updating $simpleAppName $appVersion AppLocker policy"
& git push --set-upstream origin $appNameVer
$ghExe = Join-Path -Path $PSScriptRoot -ChildPath "gh.exe"
& $ghExe auth status
if ($LastExitCode -ne 0)
{
    Write-Host
    Write-Host "Wake up! The instructions below require user interaction..." -ForegroundColor Yellow
    & $ghExe auth login
}
& $ghExe pr create --title "$simpleAppName $appVersion AppLocker Policy" --body "Approve $simpleAppName $appVersion AppLocker policy addition/changes" --head $appNameVer

# Done/cleanup
& git checkout main
& git branch -D $appNameVer
$folderToRemove = $(Join-Path -Path "$rootDir\apps" -CHildPath $simpleAppName)
if (Test-Path -Path $folderToRemove)
{
    Remove-Item -Path $folderToRemove -Recurse
}

popd

pause
