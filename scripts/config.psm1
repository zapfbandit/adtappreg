function Get-Config {
    @{
        "auth" = @{
            "clientId" = "b38ddd50-a3e4-41d5-b380-28ae8444190b"
            "authority" = "https://login.microsoftonline.com/5cf3cef3-9226-48a7-a9a3-106dba222f7c/"
            "redirectUri" = "msalb38ddd50-a3e4-41d5-b380-28ae8444190b://auth"
        }
        "storageAccount" = "deletetest3"
        "containerName" = "intune-app-files"
        
    }
}
Export-ModuleMember -Function Get-Config

# Maps target names to target ids
function Get-TargetId {
    param (
        $name
    )
    
    # TODO: maybe load from config?!?
    $map = @{
        "TestGroup" = "d251b7b9-707e-4ab6-af25-08ef9e447434"
    }
    
    $map.Get_Item($name)
}
Export-ModuleMember -Function Get-TargetId