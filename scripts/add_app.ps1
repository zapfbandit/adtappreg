Import-Module powershell-yaml

Function Test-SourceFile(){

param
(
    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    $SourceFile
)

    try {

            if(!(test-path "$SourceFile")){

            Write-Host
            Write-Host "Source File '$sourceFile' doesn't exist..." -ForegroundColor Red
            throw

            }

        }

    catch {

		Write-Host -ForegroundColor Red $_.Exception.Message;
        Write-Host
		break

    }

}

Function Get-IntuneWinXML(){

param
(
[Parameter(Mandatory=$true)]
$SourceFile,

[Parameter(Mandatory=$true)]
$fileName,

[Parameter(Mandatory=$false)]
[ValidateSet("false","true")]
[string]$removeitem = "true"
)

Test-SourceFile "$SourceFile"

$Directory = [System.IO.Path]::GetDirectoryName("$SourceFile")

Add-Type -Assembly System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead("$SourceFile")

    $zip.Entries | where {$_.Name -like "$filename" } | foreach {

    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, "$Directory\$filename", $true)

    }

$zip.Dispose()

[xml]$IntuneWinXML = gc "$Directory\$filename"

return $IntuneWinXML

if($removeitem -eq "true"){ remove-item "$Directory\$filename" }

}

function Get-DefaultReturnCodes(){

@{"returnCode" = 0;"type" = "success"}, `
@{"returnCode" = 1707;"type" = "success"}, `
@{"returnCode" = 3010;"type" = "softReboot"}, `
@{"returnCode" = 1641;"type" = "hardReboot"}, `
@{"returnCode" = 1618;"type" = "retry"}

}

function Get-DefaultAppInfo {
    $info = @{ "@odata.type" = "#microsoft.graph.win32LobApp" }
    $info.displayName = $null
    $info.description = $null
    $info.publisher = $null
    $info.largeIcon = $null
    $info.createdDateTime = $null
    $info.lastModifiedDateTime = $null
    $info.isFeatured = $false
    $info.privacyInformationUrl = $null
    $info.informationUrl = $null
    $info.owner = $null
    $info.notes = $null
    $info.fileName = "IntunePackage.intunewin"
    $info.installCommandLine = $null
    $info.uninstallCommandLine = $null
    $info.applicableArchitectures = "x64,x86"
    $info.minimumSupportedOperatingSystem = @{
        "v10_1607" = $true
    }
    $info.runAs32Bit = $false
    $info.rules = $null
    $info.installExperience = $null
    $info.returnCodes = Get-DefaultReturnCodes
    
    $info
}

function Get-TargetId {
    param (
        $name
    )
    
    $map = @{
        "Hardware" = "0"
        "Software" = "1"
        "Engineers" = "2"
    }
    
    $map.Get_Item($name)
}

function Create-AppInfo {
    param (
        $AppConfig,
        $IntuneDetectionConfig
    )
    
    # calc app info
    $app = Get-DefaultAppInfo
    
    $app.displayName = "$($AppConfig.applicationName) ($($AppConfig.appVersion))"
    $app.description = $AppConfig.description
    
    # calc install info
    $app.rules = @()
    if ($AppConfig.installInfo.ContainsKey("msi"))
    {
        $app.installExperience = @{ "runAsAccount" = $AppConfig.runAsAccount }
        $app.setupFilePath = $AppConfig.setupFile
        $app.uninstallCommandLine = "msiexec /x `"$($IntuneDetectionConfig.ApplicationInfo.MsiInfo.MsiProductCode)`""
        $app.installCommandLine = "msiexec /i `"$($AppConfig.setupFile)`""
        
        $msiExecutionContext = $IntuneDetectionConfig.ApplicationInfo.MsiInfo.MsiExecutionContext
        $msiPackageType = "DualPurpose";
        if($msiExecutionContext -eq "System") { $msiPackageType = "PerMachine" }
        elseif($msiExecutionContext -eq "User") { $msiPackageType = "PerUser" }
        $app.msiInformation = @{
            "packageType" = "$msiPackageType"
            "productCode" = "$($IntuneDetectionConfig.ApplicationInfo.MsiInfo.MsiProductCode)"
            "productName" = "$($app.displayName)"
            "productVersion" = "$($IntuneDetectionConfig.ApplicationInfo.MsiInfo.MsiProductVersion)"
            "publisher" = "$($IntuneDetectionConfig.ApplicationInfo.MsiInfo.MsiPublisher)"
            "requiresReboot" = "$($IntuneDetectionConfig.ApplicationInfo.MsiInfo.MsiRequiresReboot)"
            "upgradeCode" = "$($IntuneDetectionConfig.ApplicationInfo.MsiInfo.MsiUpgradeCode)"
        }
        
        $detectionRule = @{
            "@odata.type" = "#microsoft.graph.win32LobAppProductCodeRule"
            "ruleType" = "detection"
            "productVersion" = $IntuneDetectionConfig.ApplicationInfo.MsiInfo.MsiProductVersion
            "productVersionOperator" = "equal"
            "productCode" = $IntuneDetectionConfig.ApplicationInfo.MsiInfo.MsiProductCode
            
        }
        $app.rules += ,$detectionRule
    }
    
    # calc assignments info
    $assignments = @()
    foreach ($target in $AppConfig.assignments.available)
    {
        $assign = @{ "@odata.type" = "#microsoft.graph.mobileAppAssignment" }
        $assign.intent = "available"
        $assign.target = @{
            "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
            "groupId" = Get-TargetId $target
        }
        $assign.settings = @{ "@odata.type" = "#microsoft.graph.win32LobAppAssignmentSettings" }
        $assign.settings.notifications = "showAll"
        $assign.settings.restartSettings = $null
        $assign.settings.installTimeSettings = $null
        $assign.settings.deliveryOptimizationPriority = "notConfigured"
        
        $assignments += ,$assign
    }
    
    # calc commit
    
    # calc file
    
    $appInfo = @{
        app = $app
        assignments = $assignments
        commit = $null
        file = $null
    }
    
    $appInfo
}

# Testing
$intuneFile = "..\apps\test\wsl_update_x64.intunewin"
$config = "..\apps\test\info.yml"

$appConfigContents = Get-Content -Path $config -Raw
$appConfig = ConvertFrom-Yaml $appConfigContents
# TODO: validate appConfig contents/format

$detectionXml = Get-IntuneWinXML $intuneFile -fileName "detection.xml"

Create-AppInfo $appConfig $detectionXml
