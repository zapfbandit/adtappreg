Import-Module powershell-yaml
# Stolen codes
##########################################

##consts
$baseUrl = "https://graph.microsoft.com/v1.0/deviceAppManagement/"

$logRequestUris = $true;
$logHeaders = $false;
$logContent = $true;

$azureStorageUploadChunkSizeInMb = 6l;

$sleep = 30
##

function CloneObject($object){

	$stream = New-Object IO.MemoryStream;
	$formatter = New-Object Runtime.Serialization.Formatters.Binary.BinaryFormatter;
	$formatter.Serialize($stream, $object);
	$stream.Position = 0;
	$formatter.Deserialize($stream);
}

function MakeRequest($verb, $collectionPath, $body){

	$uri = "$baseUrl$collectionPath";
	$request = "$verb $uri";
	
	$clonedHeaders = CloneObject $authToken;
	$clonedHeaders["content-length"] = $body.Length;
	$clonedHeaders["content-type"] = "application/json";

	if ($logRequestUris) { Write-Host $request; }
	if ($logHeaders) { WriteHeaders $clonedHeaders; }
	if ($logContent) { Write-Host -ForegroundColor Gray $body; }

	try
	{
		Test-AuthToken
		$response = Invoke-RestMethod $uri -Method $verb -Headers $clonedHeaders -Body $body;
		$response;
	}
	catch
	{
		Write-Host -ForegroundColor Red $request;
		Write-Host -ForegroundColor Red $_.Exception.Message;
        
        $streamReader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
        $ErrResp = $streamReader.ReadToEnd()
        $streamReader.Close()
        Write-Host $ErrResp
        
		throw;
	}
}

function Get-AuthToken {

<#
.SYNOPSIS
This function is used to authenticate with the Graph API REST interface
.DESCRIPTION
The function authenticate with the Graph API Interface with the tenant name
.EXAMPLE
Get-AuthToken
Authenticates you with the Graph API interface
.NOTES
NAME: Get-AuthToken
#>


    try {

    $authResult = Get-MsalToken `
      -ClientId "b38ddd50-a3e4-41d5-b380-28ae8444190b" `
      -Scope "https://graph.microsoft.com/DeviceManagementApps.ReadWrite.All" `
      -Authority "https://login.microsoftonline.com/5cf3cef3-9226-48a7-a9a3-106dba222f7c/" `
      -RedirectUri "msalb38ddd50-a3e4-41d5-b380-28ae8444190b://auth"

        # If the accesstoken is valid then create the authentication header
        
        if($authResult.AccessToken){

        # Creating header for Authorization token

        $authHeader = @{
            'Content-Type'='application/json'
            'Authorization'="Bearer " + $authResult.AccessToken
            'ExpiresOn'=$authResult.ExpiresOn
            }

        return $authHeader

        }

        else {

        Write-Host
        Write-Host "Authorization Access Token is null, please re-run authentication..." -ForegroundColor Red
        Write-Host
        break

        }

    }

    catch {

    write-host $_.Exception.Message -f Red
    write-host $_.Exception.ItemName -f Red
    write-host
    break

    }

}

Function Test-AuthToken(){

    # Checking if authToken exists before running authentication
    if($global:authToken){

        # Setting DateTime to Universal time to work in all timezones
        $DateTime = (Get-Date).ToUniversalTime()

        # If the authToken exists checking when it expires
        $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes

            if($TokenExpires -le 0){

            write-host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
            write-host

            $global:authToken = Get-AuthToken -User $User

            }
    }

    # Authentication doesn't exist, calling Get-AuthToken function

    else {

    # Getting the authorization token
    $global:authToken = Get-AuthToken

    }
}

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

Function Get-IntuneWinFile(){

param
(
[Parameter(Mandatory=$true)]
$SourceFile,

[Parameter(Mandatory=$true)]
$fileName,

[Parameter(Mandatory=$false)]
[string]$Folder = "win32"
)

    $Directory = [System.IO.Path]::GetDirectoryName("$SourceFile")

    if(!(Test-Path "$Directory\$folder")){

        New-Item -ItemType Directory -Path "$Directory" -Name "$folder" | Out-Null

    }

    Add-Type -Assembly System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead("$SourceFile")

        $zip.Entries | where {$_.Name -like "$filename" } | foreach {

        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, "$Directory\$folder\$filename", $true)

        }

    $zip.Dispose()

    return "$Directory\$folder\$filename"

    if($removeitem -eq "true"){ remove-item "$Directory\$filename" }

}

function Get-DefaultReturnCodes(){

@{"returnCode" = 0;"type" = "success"}, `
@{"returnCode" = 1707;"type" = "success"}, `
@{"returnCode" = 3010;"type" = "softReboot"}, `
@{"returnCode" = 1641;"type" = "hardReboot"}, `
@{"returnCode" = 1618;"type" = "retry"}

}
############################################################

function Get-DefaultAppInfo {
    $info = @{ "@odata.type" = "#microsoft.graph.win32LobApp" }
    $info.displayName = $null
    $info.description = $null
    $info.publisher = $null
    $info.largeIcon = $null
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
        $IntuneDetectionConfig,
        $FileSize
    )
    
    # calc app info
    $app = Get-DefaultAppInfo
    
    $app.displayName = "$($AppConfig.applicationName) ($($AppConfig.appVersion))"
    $app.description = $AppConfig.description
    
    # calc install info
    $app.rules = @()
    if ($AppConfig.installInfo.ContainsKey("msi"))
    {
        $app.installExperience = @{ "runAsAccount" = $AppConfig.installInfo.runAsAccount }
        $app.setupFilePath = $AppConfig.installInfo.setupFile
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
    $commit = @{
        "fileEncryptionInfo" = @{
            "encryptionKey" = $IntuneDetectionConfig.ApplicationInfo.EncryptionInfo.EncryptionKey
            "macKey" = $IntuneDetectionConfig.ApplicationInfo.EncryptionInfo.macKey
            "initializationVector" = $IntuneDetectionConfig.ApplicationInfo.EncryptionInfo.initializationVector
            "mac" = $IntuneDetectionConfig.ApplicationInfo.EncryptionInfo.mac
            "profileIdentifier" = "ProfileVersion1"
            "fileDigest" = $IntuneDetectionConfig.ApplicationInfo.EncryptionInfo.fileDigest
            "fileDigestAlgorithm" = $IntuneDetectionConfig.ApplicationInfo.EncryptionInfo.fileDigestAlgorithm
        }
    }
    
    # calc file
    $file = @{
        "@odata.type" = "#microsoft.graph.mobileAppContentFile"
        "isDependency" = $false
        "name" = $app.fileName
        "size" = [int64]$IntuneDetectionConfig.ApplicationInfo.UnencryptedContentSize
        "sizeEncrypted" = $FileSize
        "manifest" = $null
    }
    
    $appInfo = @{
        app = $app
        assignments = $assignments
        commit = $commit
        file = $file
    }
    
    $appInfo
}

function Add-Application {
    param (
        $IntuneFile,
        $Config
    )
    
    $appConfigContents = Get-Content -Path $config -Raw
    $appConfig = ConvertFrom-Yaml $appConfigContents
    # TODO: validate appConfig contents/format

    $detectionXml = Get-IntuneWinXML $intuneFile -fileName "detection.xml"

    $intuneWinFile = Get-IntuneWinFile $intuneFile -fileName "$($detectionXml.ApplicationInfo.FileName)"
    $fileSize = (Get-Item "$intuneWinFile").Length

    $appInfo = Create-AppInfo $appConfig $detectionXml $fileSize
    
    Test-AuthToken
    
    # kinda stolen below
    $LOBType = "microsoft.graph.win32LobApp"
    $Win32Path = "$SourceFile"
    
    Write-Host
    Write-Host "Creating application in Intune..." -ForegroundColor Yellow
    $mobileApp = MakeRequest "POST" "mobileApps" ($appInfo.app | ConvertTo-Json)
}

# Testing
$intuneFile = "..\apps\test\wsl_update_x64.intunewin"
$config = "..\apps\test\info.yml"

Add-Application $intuneFile $config
