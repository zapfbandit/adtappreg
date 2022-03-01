Import-Module powershell-yaml

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
    $info.rules = $null
    $info.installExperience = $null
    $info.returnCodes = $null
    
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
        $IntunePackagePath,
        $AppConfigPath
    )
    
    $appConfigContents = Get-Content -Path $AppConfigPath -Raw
    
    $appConfig = ConvertFrom-Yaml $appConfigContents
    # TODO: validate appConfig contents/format
    
    $app = Get-DefaultAppInfo
    
    $app.displayName = "$($appInfo.applicationName) ($($appInfo.Version))"
    $app.description = $appInfo.description
    
    # calc install info
    if ([bool]$appConfig.installInfo.PSObject.Properties["msi"])
    {
        Write-Host Hello world!
    }
    
    # calc assignments info
    $assignments = @()
    foreach ($target in $appConfig.assignments.available)
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
    
    $appInfo = @{
        app = $app
        assignments = $assignments
        commit = $null
        file = $null
    }
    
    $appInfo
}

# Testing
Create-AppInfo "..\apps\test\wsl_update.x64.intunewin" "..\apps\test\info.yml"
pause