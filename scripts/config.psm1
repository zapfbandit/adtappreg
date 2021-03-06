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

# SIG # Begin signature block
# MIIf7QYJKoZIhvcNAQcCoIIf3jCCH9oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC9jo1SeZfnaAob
# ZVPX38KjjrNYnBygywqVsbYDX2yAkaCCGbswggWRMIIEeaADAgECAhMVAAAACBly
# 8cTzWvVnAAEAAAAIMA0GCSqGSIb3DQEBDQUAMCMxITAfBgNVBAMTGEFEVC1ST09U
# Q0VSVDAxLUFEVENBMjAyMDAeFw0yMTEwMjQwNDQxMzlaFw0yMjEwMjQwNDUxMzla
# MG4xEjAQBgoJkiaJk/IsZAEZFgJhdTETMBEGCgmSJomT8ixkARkWA2NvbTETMBEG
# CgmSJomT8ixkARkWA2FkdDESMBAGCgmSJomT8ixkARkWAmFkMRowGAYDVQQDExFB
# RFQtQ0VSVFNFUlYwMS1DQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# AM2UtdyF1E7J5Xnwr6184YOnk3wd3Vag6u+WVG/mrDvKWbVciJULlGbzsadIHDXH
# AVx4pePBjJigEwyzKQQXb4VcggwKG1zQBEYeqBvf72SrXkioGS9usdCZ7SwSETtC
# Hy5T8wmGkEOKzupfd29lhm5rzvJa+hnELU1UllOv7cRPCn9Q419MuaAYbY2XKA0e
# K21m4K8OtZXoRabRN620tu9iVQT/C9HkF+DglzGZ48SJFv2gxbFXNB0B+jlFrxRp
# OYRtd31XE5AeCrQ1J5sLKP1BCScHxWr3EGcMhAmbC65bc2iafKRnosq4ZV6AqGTL
# 4gdRVz3RvFnMzzfRnRwb6uJVMdkvEAWRm94vJspCndlTZaV81Zc0WI0ujWZXWRVj
# vDW4DxuhsSz5ryEvhFJPUHxOv4PDPaYYO/xwcBcAqKxx5JS21kiNGQkYsd/xz7Os
# lAE1YTPCxDnIGo+5Wz48y2zRhBTpdCVWbV4OwODlHhT2X8eQ1jiKXa6c6fUIRLue
# fkc/Co5BwWG71EfjUK6QJa8A5JiRCCkhAlnPE3cmOisonDSAMHO7oVbjK278ck7I
# nx/IhjKVIF2LzFdY8zVSCUgogATkuyvL7ftCpcu8lHpQGtzQpHoyuWTTIXHTdXtX
# Pey+88w4md8kJSZ09oOsQHDZYv2HICgrtjYz68j0BLC/AgMBAAGjggFxMIIBbTAQ
# BgkrBgEEAYI3FQEEAwIBAjAjBgkrBgEEAYI3FQIEFgQUO5+Yb02tXPYRajwUpz3s
# YNIfeX8wHQYDVR0OBBYEFBPx8yEcEeQdeZjQ8eAmAdi9Er8KMBkGCSsGAQQBgjcU
# AgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8G
# A1UdIwQYMBaAFF8c0yTQ7WUX8RdWYLh8XhabefUHME4GA1UdHwRHMEUwQ6BBoD+G
# PWh0dHA6Ly9jcmwuYWR0LmNvbS5hdS9DZXJ0RW5yb2xsL0FEVC1ST09UQ0VSVDAx
# LUFEVENBMjAyMC5jcmwwawYIKwYBBQUHAQEEXzBdMFsGCCsGAQUFBzAChk9odHRw
# Oi8vY3JsLmFkdC5jb20uYXUvQ2VydEVucm9sbC9BRFQtUk9PVENFUlQwMV9BRFQt
# Uk9PVENFUlQwMS1BRFRDQTIwMjAoMSkuY3J0MA0GCSqGSIb3DQEBDQUAA4IBAQAI
# ATHaD6F++qn0XiaGWj58OK+dUHDE832JzFR4tQEdiJQFe604dOvDsoQs+X51UrRk
# 3Yfl+sNEnzAzWhFRv5IjedtuMl011XfjDN995ogv899OqyG2fBgU6zGqFrZ3M4ka
# TRxnmeZ/A9X6ShNkqAcGP+frifm6FaVyk1jpBVmhEPD/rxNFjQZkymV0QZw3pGYW
# Dm06rZZje+mA048xzTknvTWPK17I3tCg0iqIEqewIPYUvy/v8qAhRzMcdWJGOPAE
# Vh7Nejqwc3QWQN2ZS6xqWhctInvOm5nOTXGj9xtNBFXa1Hcb3IFA9Tsqv4bqwGbQ
# ie34zzBmAitNy1H+DTCqMIIGODCCBCCgAwIBAgITOgAAASX5BO4qbgcSmgACAAAB
# JTANBgkqhkiG9w0BAQ0FADBuMRIwEAYKCZImiZPyLGQBGRYCYXUxEzARBgoJkiaJ
# k/IsZAEZFgNjb20xEzARBgoJkiaJk/IsZAEZFgNhZHQxEjAQBgoJkiaJk/IsZAEZ
# FgJhZDEaMBgGA1UEAxMRQURULUNFUlRTRVJWMDEtQ0EwHhcNMjExMDI5MDM1NDA4
# WhcNMjIxMDI0MDQ1MTM5WjCBhjESMBAGCgmSJomT8ixkARkWAmF1MRMwEQYKCZIm
# iZPyLGQBGRYDY29tMRMwEQYKCZImiZPyLGQBGRYDYWR0MRIwEAYKCZImiZPyLGQB
# GRYCYWQxDDAKBgNVBAsTA0FEVDEOMAwGA1UECxMFVXNlcnMxFDASBgNVBAMTC0ln
# b3IgRG9waXRhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlcSeKObD
# PkuodS8zlD3aHjgUy49YwjYLjIqiUJHYqlGdUrHT9Hy4xiRGFPMZ8kETK7dVXYe6
# DQrwP57a1wVrpv9gvBbeW2wFVNqbQn0rLoeaiUSUNjOuG1sP4VrjKxppqeLWImkE
# v0jgqF081QgVkFZ5pzGaMiGmhe3WqBM7OP+p4u0z/dAiEwyB1cMiMQjltz3TVtlH
# wfqPYahO3SfRTbLlrM9FDMr2E8O/Kn5trtc7Vws/nrx/py68ozP8omsaw+abj+y6
# HC0zBUg9lSUYzT0nUtlBwYG4efRtOQnTZ6D30CskoNGzqc6fdsOhA0HprmaDNEhi
# rmi29QRL7RzcUQIDAQABo4IBtDCCAbAwPAYJKwYBBAGCNxUHBC8wLQYlKwYBBAGC
# NxUIgcXOZoSihDKGnZMDg6+AcN75MVODncYZgfvgcwIBZAIBAzATBgNVHSUEDDAK
# BggrBgEFBQcDAzAOBgNVHQ8BAf8EBAMCB4AwGwYJKwYBBAGCNxUKBA4wDDAKBggr
# BgEFBQcDAzAxBgNVHREEKjAooCYGCisGAQQBgjcUAgOgGAwWaWdvci5kb3BpdGFA
# YWR0LmNvbS5hdTAdBgNVHQ4EFgQUjwBt76aoMAEXpmvH/EehrbbJ9v4wHwYDVR0j
# BBgwFoAUE/HzIRwR5B15mNDx4CYB2L0SvwowRwYDVR0fBEAwPjA8oDqgOIY2aHR0
# cDovL2NybC5hZHQuY29tLmF1L0NlcnRFbnJvbGwvQURULUNFUlRTRVJWMDEtQ0Eu
# Y3JsMHIGCCsGAQUFBwEBBGYwZDBiBggrBgEFBQcwAoZWaHR0cDovL2NybC5hZHQu
# Y29tLmF1L0NlcnRFbnJvbGwvQURULUNFUlRTRVJWMDEuYWQuYWR0LmNvbS5hdV9B
# RFQtQ0VSVFNFUlYwMS1DQSgyKS5jcnQwDQYJKoZIhvcNAQENBQADggIBACEyzX+3
# gil0lTlHcrsuPJV+nx4b5IUtQtvM8AKFWkIE86G+PJHLxIeiAjt7Pq5d+NzGEBBZ
# LZ51YDdh0uFBZLkhhp2QpG5jurS/DMQ90Y4cmx1/vPrx/xIYWnxwQ18b0/rTW+cO
# 4tk7wlGVOeq70tZwEnnPErPZmGQuHPbKRFL394MRC/4hixbiULmK7v5fx2o8I27C
# oo9AVg+JRvlyOXp66m5VyF+eVVauobDiAIkLsH2Qhp3m1MXkyd3uJI1b8DJOBNED
# snlaUwFmRZdkhAx0TbesXd7EOUzAaLOLkq90LWtHL43cra9zJvev3lqeRMdnEu5m
# 699ebzvte+OrlFrr2oVMZkN06sQuxsIYPatR0Vft0EW25OBK26rIfl3L5X8HLJLS
# pFtj5wqdAo7p/zvtS5HTG040PHpkwvNVTZSYzbGiiCNhBdXbR9j/6PFybyj7m+Di
# UmIUslzhhjFRiyqaP4HCebmYspvkbz6aPOrC2pKgmQ8Hm5nYI0EDlUv4+O0EmR8T
# WjZeg/y4b+KMBvrND6+zX/8S8npCoB7qNbOcix7I1ud5Xp6nONbN6zH7xtuU9dwJ
# 7NuxUcj4NaLS779YRJM2v+32YBThFiXbxjnuUst6k9uL17CHi7JVyR+C8Sg7NYQx
# pXo2x28FfmTz/+yre/xf+vGrIsqmpuhQrrBvMIIG7DCCBNSgAwIBAgIQMA9vrN1m
# mHR8qUY2p3gtuTANBgkqhkiG9w0BAQwFADCBiDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNleSBDaXR5MR4wHAYDVQQKExVU
# aGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMTJVVTRVJUcnVzdCBSU0EgQ2Vy
# dGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTkwNTAyMDAwMDAwWhcNMzgwMTE4MjM1
# OTU5WjB9MQswCQYDVQQGEwJHQjEbMBkGA1UECBMSR3JlYXRlciBNYW5jaGVzdGVy
# MRAwDgYDVQQHEwdTYWxmb3JkMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxJTAj
# BgNVBAMTHFNlY3RpZ28gUlNBIFRpbWUgU3RhbXBpbmcgQ0EwggIiMA0GCSqGSIb3
# DQEBAQUAA4ICDwAwggIKAoICAQDIGwGv2Sx+iJl9AZg/IJC9nIAhVJO5z6A+U++z
# WsB21hoEpc5Hg7XrxMxJNMvzRWW5+adkFiYJ+9UyUnkuyWPCE5u2hj8BBZJmbyGr
# 1XEQeYf0RirNxFrJ29ddSU1yVg/cyeNTmDoqHvzOWEnTv/M5u7mkI0Ks0BXDf56i
# XNc48RaycNOjxN+zxXKsLgp3/A2UUrf8H5VzJD0BKLwPDU+zkQGObp0ndVXRFzs0
# IXuXAZSvf4DP0REKV4TJf1bgvUacgr6Unb+0ILBgfrhN9Q0/29DqhYyKVnHRLZRM
# yIw80xSinL0m/9NTIMdgaZtYClT0Bef9Maz5yIUXx7gpGaQpL0bj3duRX58/Nj4O
# MGcrRrc1r5a+2kxgzKi7nw0U1BjEMJh0giHPYla1IXMSHv2qyghYh3ekFesZVf/Q
# OVQtJu5FGjpvzdeE8NfwKMVPZIMC1Pvi3vG8Aij0bdonigbSlofe6GsO8Ft96XZp
# kyAcSpcsdxkrk5WYnJee647BeFbGRCXfBhKaBi2fA179g6JTZ8qx+o2hZMmIklnL
# qEbAyfKm/31X2xJ2+opBJNQb/HKlFKLUrUMcpEmLQTkUAx4p+hulIq6lw02C0I3a
# a7fb9xhAV3PwcaP7Sn1FNsH3jYL6uckNU4B9+rY5WDLvbxhQiddPnTO9GrWdod6V
# QXqngwIDAQABo4IBWjCCAVYwHwYDVR0jBBgwFoAUU3m/WqorSs9UgOHYm8Cd8rID
# ZsswHQYDVR0OBBYEFBqh+GEZIA/DQXdFKI7RNV8GEgRVMA4GA1UdDwEB/wQEAwIB
# hjASBgNVHRMBAf8ECDAGAQH/AgEAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBEGA1Ud
# IAQKMAgwBgYEVR0gADBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwOi8vY3JsLnVzZXJ0
# cnVzdC5jb20vVVNFUlRydXN0UlNBQ2VydGlmaWNhdGlvbkF1dGhvcml0eS5jcmww
# dgYIKwYBBQUHAQEEajBoMD8GCCsGAQUFBzAChjNodHRwOi8vY3J0LnVzZXJ0cnVz
# dC5jb20vVVNFUlRydXN0UlNBQWRkVHJ1c3RDQS5jcnQwJQYIKwYBBQUHMAGGGWh0
# dHA6Ly9vY3NwLnVzZXJ0cnVzdC5jb20wDQYJKoZIhvcNAQEMBQADggIBAG1UgaUz
# XRbhtVOBkXXfA3oyCy0lhBGysNsqfSoF9bw7J/RaoLlJWZApbGHLtVDb4n35nwDv
# QMOt0+LkVvlYQc/xQuUQff+wdB+PxlwJ+TNe6qAcJlhc87QRD9XVw+K81Vh4v0h2
# 4URnbY+wQxAPjeT5OGK/EwHFhaNMxcyyUzCVpNb0llYIuM1cfwGWvnJSajtCN3wW
# eDmTk5SbsdyybUFtZ83Jb5A9f0VywRsj1sJVhGbks8VmBvbz1kteraMrQoohkv6o
# b1olcGKBc2NeoLvY3NdK0z2vgwY4Eh0khy3k/ALWPncEvAQ2ted3y5wujSMYuaPC
# Rx3wXdahc1cFaJqnyTdlHb7qvNhCg0MFpYumCf/RoZSmTqo9CfUFbLfSZFrYKiLC
# S53xOV5M3kg9mzSWmglfjv33sVKRzj+J9hyhtal1H3G/W0NdZT1QgW6r8NDT/LKz
# H7aZlib0PHmLXGTMze4nmuWgwAxyh8FuTVrTHurwROYybxzrF06Uw3hlIDsPQaof
# 6aFBnf6xuKBlKjTg3qj5PObBMLvAoGMs/FwWAKjQxH/qEZ0eBsambTJdtDgJK0kH
# qv3sMNrxpy/Pt/360KOE2See+wFmd7lWEOEgbsausfm2usg1XTN2jvF8IAwqd661
# ogKGuinutFoAsYyr4/kKyVRd1LlqdJ69SK6YMIIG9jCCBN6gAwIBAgIRAJA5f5rS
# SjoT8r2RXwg4qUMwDQYJKoZIhvcNAQEMBQAwfTELMAkGA1UEBhMCR0IxGzAZBgNV
# BAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UE
# ChMPU2VjdGlnbyBMaW1pdGVkMSUwIwYDVQQDExxTZWN0aWdvIFJTQSBUaW1lIFN0
# YW1waW5nIENBMB4XDTIyMDUxMTAwMDAwMFoXDTMzMDgxMDIzNTk1OVowajELMAkG
# A1UEBhMCR0IxEzARBgNVBAgTCk1hbmNoZXN0ZXIxGDAWBgNVBAoTD1NlY3RpZ28g
# TGltaXRlZDEsMCoGA1UEAwwjU2VjdGlnbyBSU0EgVGltZSBTdGFtcGluZyBTaWdu
# ZXIgIzMwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCQsnE/eeHUuYoX
# zMOXwpCUcu1aOm8BQ39zWiifJHygNUAG+pSvCqGDthPkSxUGXmqKIDRxe7slrT9b
# CqQfL2x9LmFR0IxZNz6mXfEeXYC22B9g480Saogfxv4Yy5NDVnrHzgPWAGQoViKx
# SxnS8JbJRB85XZywlu1aSY1+cuRDa3/JoD9sSq3VAE+9CriDxb2YLAd2AXBF3sPw
# Qmnq/ybMA0QfFijhanS2nEX6tjrOlNEfvYxlqv38wzzoDZw4ZtX8fR6bWYyRWkJX
# VVAWDUt0cu6gKjH8JgI0+WQbWf3jOtTouEEpdAE/DeATdysRPPs9zdDn4ZdbVfcq
# A23VzWLazpwe/OpwfeZ9S2jOWilh06BcJbOlJ2ijWP31LWvKX2THaygM2qx4Qd6S
# 7w/F7KvfLW8aVFFsM7ONWWDn3+gXIqN5QWLP/Hvzktqu4DxPD1rMbt8fvCKvtzgQ
# mjSnC//+HV6k8+4WOCs/rHaUQZ1kHfqA/QDh/vg61MNeu2lNcpnl8TItUfphrU3q
# Jo5t/KlImD7yRg1psbdu9AXbQQXGGMBQ5Pit/qxjYUeRvEa1RlNsxfThhieThDls
# deAdDHpZiy7L9GQsQkf0VFiFN+XHaafSJYuWv8at4L2xN/cf30J7qusc6es9Wt34
# 0pDVSZo6HYMaV38cAcLOHH3M+5YVxQIDAQABo4IBgjCCAX4wHwYDVR0jBBgwFoAU
# GqH4YRkgD8NBd0UojtE1XwYSBFUwHQYDVR0OBBYEFCUuaDxrmiskFKkfot8mOs8U
# pvHgMA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoG
# CCsGAQUFBwMIMEoGA1UdIARDMEEwNQYMKwYBBAGyMQECAQMIMCUwIwYIKwYBBQUH
# AgEWF2h0dHBzOi8vc2VjdGlnby5jb20vQ1BTMAgGBmeBDAEEAjBEBgNVHR8EPTA7
# MDmgN6A1hjNodHRwOi8vY3JsLnNlY3RpZ28uY29tL1NlY3RpZ29SU0FUaW1lU3Rh
# bXBpbmdDQS5jcmwwdAYIKwYBBQUHAQEEaDBmMD8GCCsGAQUFBzAChjNodHRwOi8v
# Y3J0LnNlY3RpZ28uY29tL1NlY3RpZ29SU0FUaW1lU3RhbXBpbmdDQS5jcnQwIwYI
# KwYBBQUHMAGGF2h0dHA6Ly9vY3NwLnNlY3RpZ28uY29tMA0GCSqGSIb3DQEBDAUA
# A4ICAQBz2u1ocsvCuUChMbu0A6MtFHsk57RbFX2o6f2t0ZINfD02oGnZ85ow2qxp
# 1nRXJD9+DzzZ9cN5JWwm6I1ok87xd4k5f6gEBdo0wxTqnwhUq//EfpZsK9OU67Rs
# 4EVNLLL3OztatcH714l1bZhycvb3Byjz07LQ6xm+FSx4781FoADk+AR2u1fFkL53
# VJB0ngtPTcSqE4+XrwE1K8ubEXjp8vmJBDxO44ISYuu0RAx1QcIPNLiIncgi8RNq
# 2xgvbnitxAW06IQIkwf5fYP+aJg05Hflsc6MlGzbA20oBUd+my7wZPvbpAMxEHwa
# +zwZgNELcLlVX0e+OWTOt9ojVDLjRrIy2NIphskVXYCVrwL7tNEunTh8NeAPHO0b
# R0icImpVgtnyughlA+XxKfNIigkBTKZ58qK2GpmU65co4b59G6F87VaApvQiM5Dk
# hFP8KvrAp5eo6rWNes7k4EuhM6sLdqDVaRa3jma/X/ofxKh/p6FIFJENgvy9TZnt
# yeZsNv53Q5m4aS18YS/to7BJ/lu+aSSR/5P8V2mSS9kFP22GctOi0MBk0jpCwRoD
# +9DtmiG4P6+mslFU1UzFyh8SjVfGOe1c/+yfJnatZGZn6Kow4NKtt32xakEnbgOK
# o3TgigmCbr/j9re8ngspGGiBoZw/bhZZSxQJCZrmrr9gFd2G9TGCBYgwggWEAgEB
# MIGFMG4xEjAQBgoJkiaJk/IsZAEZFgJhdTETMBEGCgmSJomT8ixkARkWA2NvbTET
# MBEGCgmSJomT8ixkARkWA2FkdDESMBAGCgmSJomT8ixkARkWAmFkMRowGAYDVQQD
# ExFBRFQtQ0VSVFNFUlYwMS1DQQITOgAAASX5BO4qbgcSmgACAAABJTANBglghkgB
# ZQMEAgEFAKCBhDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJ
# AzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8G
# CSqGSIb3DQEJBDEiBCAMNUQ6HbagQC5vv0zpReDvt7hpUDPuKwCU3wxxaQO5pDAN
# BgkqhkiG9w0BAQEFAASCAQBQ3kWXA+HZyStzM27PtS7WPlAQPwTIv0RWknqBe+U6
# DwgXSoHVJADKmj90M45q5ZfNE1aQjBalXFWiM8FR2xpejGO5NGHtoT3BMdc3I7o2
# ESYjpVf3sCBIPiqYpJ1iYcc9osV3xVVrha0FEbqVSIYBk/2qbFchzM65vPP2KIHr
# A95f8BCsB5Hi8Eryrf295UjTtXE7Or2M4qdO3o3O4vO/1TJrGv1RzCDsc3vtBLeq
# CqMdvvFiififTKutxCI7+4DCoNJhF5VePJex+1GNHTOm61Weg1i2iaKPQ4eBE965
# rBofU0wwSxxesC7O4xQoGy8WZGSXPbjP1Si7xxyOQGHeoYIDTDCCA0gGCSqGSIb3
# DQEJBjGCAzkwggM1AgEBMIGSMH0xCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVh
# dGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZvcmQxGDAWBgNVBAoTD1NlY3Rp
# Z28gTGltaXRlZDElMCMGA1UEAxMcU2VjdGlnbyBSU0EgVGltZSBTdGFtcGluZyBD
# QQIRAJA5f5rSSjoT8r2RXwg4qUMwDQYJYIZIAWUDBAICBQCgeTAYBgkqhkiG9w0B
# CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yMjA1MjYyMzU0NTJaMD8G
# CSqGSIb3DQEJBDEyBDAzSx00qB8AbABwx8jMKRzVl5mC+lDGTtCUYQiE6oN1FVsS
# 7FDrTtY3S9sXPlBBm9gwDQYJKoZIhvcNAQEBBQAEggIAgVrQlmjrXSmjQCuNu0zP
# L26VqG6DV3dpLC8QaTOj6AHruZkhmQseBFFA6OL83CLWBG6nGCR53PbrqZp1UZyl
# YA+eOEjMoXdGa01XUO/RbDjKxl/qtOJ8xZTMk1lrsQxkmNj5iT33ozzNt6Av9WBn
# cVANGnUIYHf48mAcJxPbWVA/8TZegmuDKuqBunrzqEyEyURwzMGm3HuePlXreBQH
# fotVDAj/syQ13a40vpPuAmLPs/OAm77SVG639njFjnDKyIlRcyCJaMC4qL/sxZ85
# lndepag/JD1tP0iYsyeq70uX8YwpfSoRie/6JW2KHBvLbOGl+6RG0Jkt1DOsprpS
# yAuPg5n59sbBFgWmbcuIce3Na7Pp/qP15Y4RoxDcpw53SE9JpsJS/IrfZH0pDFbG
# cTJreIBWq3BJ4peRuAwANNyuoriy6CygDxlF2T38AuwKDCPE0wyz7DRt6v9LY5yn
# 6MPtn8KxLOKrJevIVMRfaMm8BWKsQr7po1Dj6VVZtQ8bV3mMYHBHzwOiKkmIseET
# i3NU2VRmxETScpPB0W+GdVs9s5kH/pT4jD2SCSzOvFCwqa0PgAyVTqnoeQrZp0um
# oAMvD9HLPhJ+VzqrWh41Php0KoonyTLUUmC87fkqxzCpm3cUB8z1o/fXIWplROAX
# ZspucqxFo21iy+dHrHAgXp4=
# SIG # End signature block
