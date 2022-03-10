Import-Module -Name $(Join-Path -Path $PSScriptRoot -ChildPath "yaml\powershell-yaml")
Import-Module -Name $(Join-Path -Path $PSScriptRoot -ChildPath "config")
# Stolen codes
##########################################

##consts
$baseUrl = "https://graph.microsoft.com/v1.0/deviceAppManagement/"

$logRequestUris = $true;
$logHeaders = $false;
$logContent = $true;

$azureStorageUploadChunkSizeInMb = 6l;

$connectionConfig = Get-Config

$sleep = 30
##

function FinalizeAzureStorageUpload($sasUri, $ids){

	$uri = "$sasUri&comp=blocklist";
	$request = "PUT $uri";

	$xml = '<?xml version="1.0" encoding="utf-8"?><BlockList>';
	foreach ($id in $ids)
	{
		$xml += "<Latest>$id</Latest>";
	}
	$xml += '</BlockList>';

	if ($logRequestUris) { Write-Host $request; }
	if ($logContent) { Write-Host -ForegroundColor Gray $xml; }

	try
	{
		Invoke-RestMethod $uri -Method Put -Body $xml;
	}
	catch
	{
		Write-Host -ForegroundColor Red $request;
		Write-Host -ForegroundColor Red $_.Exception.Message;
		throw;
	}
}

function RenewAzureStorageUpload($fileUri){

	$renewalUri = "$fileUri/renewUpload";
	$actionBody = "";
	$rewnewUriResult = MakePostRequest $renewalUri $actionBody;
	
	$file = WaitForFileProcessing $fileUri "AzureStorageUriRenewal" $azureStorageRenewSasUriBackOffTimeInSeconds;

}

function UploadAzureStorageChunk($sasUri, $id, $body){

	$uri = "$sasUri&comp=block&blockid=$id";
	$request = "PUT $uri";

	$iso = [System.Text.Encoding]::GetEncoding("iso-8859-1");
	$encodedBody = $iso.GetString($body);
	$headers = @{
		"x-ms-blob-type" = "BlockBlob"
	};

	if ($logRequestUris) { Write-Host $request; }
	if ($logHeaders) { WriteHeaders $headers; }

	try
	{
		$response = Invoke-WebRequest $uri -Method Put -Headers $headers -Body $encodedBody;
	}
	catch
	{
		Write-Host -ForegroundColor Red $request;
		Write-Host -ForegroundColor Red $_.Exception.Message;
		throw;
	}

}

function UploadFileToAzureStorage($sasUri, $filepath, $fileUri){

	try {

        $chunkSizeInBytes = 1024l * 1024l * $azureStorageUploadChunkSizeInMb;
		
		# Start the timer for SAS URI renewal.
		$sasRenewalTimer = [System.Diagnostics.Stopwatch]::StartNew()
		
		# Find the file size and open the file.
		$fileSize = (Get-Item $filepath).length;
		$chunks = [Math]::Ceiling($fileSize / $chunkSizeInBytes);
		$reader = New-Object System.IO.BinaryReader([System.IO.File]::Open($filepath, [System.IO.FileMode]::Open));
		$position = $reader.BaseStream.Seek(0, [System.IO.SeekOrigin]::Begin);
		
		# Upload each chunk. Check whether a SAS URI renewal is required after each chunk is uploaded and renew if needed.
		$ids = @();

		for ($chunk = 0; $chunk -lt $chunks; $chunk++){

			$id = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($chunk.ToString("0000")));
			$ids += $id;

			$start = $chunk * $chunkSizeInBytes;
			$length = [Math]::Min($chunkSizeInBytes, $fileSize - $start);
			$bytes = $reader.ReadBytes($length);
			
			$currentChunk = $chunk + 1;			

            Write-Progress -Activity "Uploading File to Azure Storage" -status "Uploading chunk $currentChunk of $chunks" `
            -percentComplete ($currentChunk / $chunks*100)

            $uploadResponse = UploadAzureStorageChunk $sasUri $id $bytes;
			
			# Renew the SAS URI if 7 minutes have elapsed since the upload started or was renewed last.
			if ($currentChunk -lt $chunks -and $sasRenewalTimer.ElapsedMilliseconds -ge 450000){

				$renewalResponse = RenewAzureStorageUpload $fileUri;
				$sasRenewalTimer.Restart();
			
            }

		}

        Write-Progress -Completed -Activity "Uploading File to Azure Storage"

		$reader.Close();

	}

	finally {

		if ($reader -ne $null) { $reader.Dispose(); }
	
    }
	
	# Finalize the upload.
	$uploadResponse = FinalizeAzureStorageUpload $sasUri $ids;

}

function MakeGetRequest($collectionPath){

	$uri = "$baseUrl$collectionPath";
	$request = "GET $uri";
	
	if ($logRequestUris) { Write-Host $request; }
	if ($logHeaders) { WriteHeaders $authToken; }

	try
	{
		Test-AuthToken
		$response = Invoke-RestMethod $uri -Method Get -Headers $authToken;
		$response;
	}
	catch
	{
		Write-Host -ForegroundColor Red $request;
		Write-Host -ForegroundColor Red $_.Exception.Message;
		throw;
	}
}

function WaitForFileProcessing($fileUri, $stage){

	$attempts= 600;
	$waitTimeInSeconds = 10;

	$successState = "$($stage)Success";
	$pendingState = "$($stage)Pending";
	$failedState = "$($stage)Failed";
	$timedOutState = "$($stage)TimedOut";

	$file = $null;
	while ($attempts -gt 0)
	{
		$file = MakeGetRequest $fileUri;

		if ($file.uploadState -eq $successState)
		{
			break;
		}
		elseif ($file.uploadState -ne $pendingState)
		{
			Write-Host -ForegroundColor Red $_.Exception.Message;
            throw "File upload state is not success: $($file.uploadState)";
		}

		Start-Sleep $waitTimeInSeconds;
		$attempts--;
	}

	if ($file -eq $null -or $file.uploadState -ne $successState)
	{
		throw "File request did not complete in the allotted time.";
	}

	$file;
}

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
      -ClientId $connectionConfig.auth.clientId `
      -Scope "https://graph.microsoft.com/DeviceManagementApps.ReadWrite.All" `
      -Authority $connectionConfig.auth.authority `
      -RedirectUri $connectionConfig.auth.redirectUri

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
        $app.installCommandLine = "msiexec /i `"$($AppConfig.installInfo.setupFile)`""
        
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
        $LocalSetupFiles, # TODO: make this a list?!?
        $Config
    )
    
    # consts?!?
    $storageAcc = $connectionConfig.storageAccount
    $containerName = $connectionConfig.containerName
    $azcopyExe = Join-Path -Path $PSScriptRoot -ChildPath "azcopy.exe"
    $intuneWinAppUtilExe = Join-Path -Path $PSScriptRoot -ChildPath "IntuneWinAppUtil.exe"
    
    # TODO: cleanup on failure
    # TODO: handle failure
    
    $appConfigContents = Get-Content -Path $config -Raw
    $appConfig = ConvertFrom-Yaml $appConfigContents
    # TODO: validate appConfig contents/format
    
    Write-Host
    Write-Host "Getting permissions..." -ForegroundColor Yellow
    Test-AuthToken
    
    # create intune file
    Write-Host
    Write-Host "Creating application intune file..." -ForegroundColor Yellow
    $tempDir = "C:\adt_temp"
    if (Test-Path $tempDir)
    {
        Remove-Item -path $tempDir -recurse
    }
    New-Item -path "C:\" -name "adt_temp" -ItemType "directory"
    New-Item -path $tempDir -name "setup_files" -ItemType "directory"
    New-Item -path $tempDir -name "output" -ItemType "directory"
    $remoteDir = Join-Path -Path $tempDir -ChildPath "remote_files" # TODO: unused?!?
    $setupDir = Join-Path -Path $tempDir -ChildPath "setup_files"
    $outputDir = Join-Path -Path $tempDir -ChildPath "output"
    # Download remote 
    if ($appConfig.installInfo.remoteFilesPaths -ne $null)
    {
        & $azcopyExe login status
        if ($LastExitCode -ne 0)
        {
            Write-Host
            Write-Host "Wake up! The instructions below require user interaction..." -ForegroundColor Yellow
            & $azcopyExe login
        }
        
        foreach ($dir in $appConfig.installInfo.remoteFilesPaths)
        {
            & $azcopyExe copy "https://$storageAcc.blob.core.windows.net/$containerName/$dir/*" $setupDir --recursive
        }
    }
    # Copy local files
    if ($LocalSetupFiles -ne $null)
    {
        $allFilesInFolder = Join-Path -Path $LocalSetupFiles -ChildPath "*"
        Copy-Item -Path $allFilesInFolder -Destination $setupDir
    }
    # TODO: call app using absolute path
    $setupFile = $appConfig.installInfo.setupFile
    & $intuneWinAppUtilExe -c $setupDir -s $setupFile -o $outputDir
    # TODO: this feels very fragile - convert to function so it is easier to fix
    $intuneFile = Join-Path -Path $outputDir -ChildPath "$($setupFile -replace `"\.[^\.]*$`", `"`").intunewin"
    
    # Extract intune info
    $detectionXml = Get-IntuneWinXML $intuneFile -fileName "detection.xml"

    $intuneWinFile = Get-IntuneWinFile $intuneFile -fileName "$($detectionXml.ApplicationInfo.FileName)"
    $fileSize = (Get-Item "$intuneWinFile").Length

    $appInfo = Create-AppInfo $appConfig $detectionXml $fileSize
    
    # kinda stolen below
    $LOBType = "microsoft.graph.win32LobApp"
    $Win32Path = "$SourceFile"
    
    Write-Host
    Write-Host "Creating application in Intune..." -ForegroundColor Yellow
    $mobileApp = MakeRequest "POST" "mobileApps" ($appInfo.app | ConvertTo-Json)
    
    # Get the content version for the new app (this will always be 1 until the new app is committed).
    Write-Host
    Write-Host "Creating Content Version in the service for the application..." -ForegroundColor Yellow
    $appId = $mobileApp.id
    $contentVersionUri = "mobileApps/$appId/$LOBType/contentVersions"
    $contentVersion = MakeRequest "POST" $contentVersionUri "{}"

    # Create a new file for the app.
    Write-Host
    Write-Host "Creating a new file entry in Azure for the upload..." -ForegroundColor Yellow
    $contentVersionId = $contentVersion.id
    $filesUri = "mobileApps/$appId/$LOBType/contentVersions/$contentVersionId/files"
    $file = MakeRequest "POST" $filesUri ($appInfo.file | ConvertTo-Json)
    
    # Wait for the service to process the new file request.
    Write-Host
    Write-Host "Waiting for the file entry URI to be created..." -ForegroundColor Yellow
    $fileId = $file.id
    $fileUri = "mobileApps/$appId/$LOBType/contentVersions/$contentVersionId/files/$fileId"
    $file = WaitForFileProcessing $fileUri "AzureStorageUriRequest"
    
    # Upload the content to Azure Storage.
    Write-Host
    Write-Host "Uploading file to Azure Storage..." -f Yellow

    $sasUri = $file.azureStorageUri
    UploadFileToAzureStorage $file.azureStorageUri "$intuneWinFile" $fileUri

    # Need to Add removal of IntuneWin file
    $IntuneWinFolder = [System.IO.Path]::GetDirectoryName("$intuneWinFile")
    Remove-Item "$intuneWinFile" -Force
    
    # Commit the file.
    Write-Host
    Write-Host "Committing the file into Azure Storage..." -ForegroundColor Yellow
    $commitFileUri = "mobileApps/$appId/$LOBType/contentVersions/$contentVersionId/files/$fileId/commit";
    MakeRequest "POST" $commitFileUri ($appInfo.commit | ConvertTo-Json);
    
    # Wait for the service to process the commit file request.
    Write-Host
    Write-Host "Waiting for the service to process the commit file request..." -ForegroundColor Yellow
    $file = WaitForFileProcessing $fileUri "CommitFile";

    # Commit the app.
    Write-Host
    Write-Host "Committing the file into Azure Storage..." -ForegroundColor Yellow
    $commitAppUri = "mobileApps/$appId";
    $commitAppBody = @{
        "@odata.type" = "#$LOBType"
        "committedContentVersion" = $contentVersionId
    }
    MakeRequest "PATCH" $commitAppUri ($commitAppBody | ConvertTo-Json);
    
    Write-Host "Sleeping for $sleep seconds to allow patch completion..." -f Magenta
    Start-Sleep $sleep
    Write-Host
    
    # Add assignments to app
    Write-Host
    Write-Host "Adding assignments..." -ForegroundColor Yellow
    $listAssignmentsUri = "mobileApps/$appId/assignments"
    foreach ($target in $appInfo.assignments)
    {
        MakeRequest "POST" $listAssignmentsUri $($target | ConvertTo-Json)
    }
    
    # Done!
    Write-Host
    Write-Host "Done..." -ForegroundColor Yellow
}

Export-ModuleMember -Function Add-Application
