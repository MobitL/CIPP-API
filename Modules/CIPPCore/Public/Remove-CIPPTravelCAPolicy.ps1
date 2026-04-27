function Remove-CIPPTravelCAPolicy {
    [CmdletBinding()]
    param(
        [string]$TenantFilter,
        [string]$PolicyName,
        [string[]]$UserMembers,
        $Headers
    )
    try {
        # Find and delete the travel CA policy by display name
        $Policies = New-GraphGetRequest `
            -uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies?`$filter=displayName eq '$PolicyName'&`$select=id,displayName" `
            -tenantid $TenantFilter -asApp $true

        if (-not $Policies) {
            Write-LogMessage -headers $Headers -API 'Remove-CIPPTravelCAPolicy' `
                -message "Travel policy '$PolicyName' not found, may already be deleted" `
                -Sev 'Info' -tenant $TenantFilter
            return "Policy '$PolicyName' not found or already deleted"
        }

        foreach ($Policy in $Policies) {
            $null = New-GraphPOSTRequest `
                -uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies/$($Policy.id)" `
                -tenantid $TenantFilter -type DELETE -body '' -asApp $true
            Write-LogMessage -headers $Headers -API 'Remove-CIPPTravelCAPolicy' `
                -message "Deleted travel CA policy: $($Policy.displayName)" `
                -Sev 'Info' -tenant $TenantFilter
        }

        # Find and delete the associated country Named Location if it exists
        $CountryLocationName = $PolicyName -replace 'CIPP_TravelPolicy_', 'CIPP_Travel_'
        $Locations = New-GraphGetRequest `
            -uri "https://graph.microsoft.com/beta/identity/conditionalAccess/namedLocations?`$filter=displayName eq '$CountryLocationName'&`$select=id,displayName" `
            -tenantid $TenantFilter -asApp $true

        foreach ($Loc in $Locations) {
            $null = New-GraphPOSTRequest `
                -uri "https://graph.microsoft.com/beta/identity/conditionalAccess/namedLocations/$($Loc.id)" `
                -tenantid $TenantFilter -type DELETE -body '' -asApp $true
            Write-LogMessage -headers $Headers -API 'Remove-CIPPTravelCAPolicy' `
                -message "Deleted country Named Location: $($Loc.displayName)" `
                -Sev 'Info' -tenant $TenantFilter
        }

        #region --- Remove users from CIPP_TravelingUsers only if no other active travel policies ---
        if ($UserMembers -and $UserMembers.Count -gt 0) {
            # Check for other active CIPP_TravelPolicy policies
            $ActiveTravelPolicies = New-GraphGetRequest `
                -uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies?`$filter=startswith(displayName,'CIPP_TravelPolicy_')&`$select=id,displayName" `
                -tenantid $TenantFilter -asApp $true

            # Exclude the policy we just deleted
            $RemainingPolicies = @($ActiveTravelPolicies | Where-Object { $_.displayName -ne $PolicyName })

            if ($RemainingPolicies.Count -eq 0) {
                # No other active travel policies - safe to remove users from group
                $TravelGroup = New-GraphGetRequest `
                    -uri "https://graph.microsoft.com/beta/groups?`$filter=displayName eq 'CIPP_TravelingUsers'&`$select=id,displayName&`$count=true" `
                    -tenantid $TenantFilter -asApp $true -ComplexFilter

                if ($TravelGroup) {
                    foreach ($Member in $UserMembers) {
                        try {
                            Remove-CIPPGroupMember -GroupId $TravelGroup[0].id -Member $Member -TenantFilter $TenantFilter -APIName 'Remove-CIPPTravelCAPolicy'
                            Write-LogMessage -headers $Headers -API 'Remove-CIPPTravelCAPolicy' `
                                -message "Removed $Member from CIPP_TravelingUsers (no remaining active travel policies)" `
                                -Sev 'Info' -tenant $TenantFilter
                        } catch {
                            Write-LogMessage -headers $Headers -API 'Remove-CIPPTravelCAPolicy' `
                                -message "Failed to remove $Member from CIPP_TravelingUsers: $($_.Exception.Message)" `
                                -Sev 'Warning' -tenant $TenantFilter
                        }
                    }
                }
            } else {
                Write-LogMessage -headers $Headers -API 'Remove-CIPPTravelCAPolicy' `
                    -message "Skipping group removal for policy '$PolicyName' - user(s) still have $($RemainingPolicies.Count) active travel policy(s): $($RemainingPolicies.displayName -join ', ')" `
                    -Sev 'Info' -tenant $TenantFilter
            }
        }
        #endregion

        return "Successfully deleted travel policy '$PolicyName' and associated resources"

    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Headers -API 'Remove-CIPPTravelCAPolicy' `
            -message "Failed to delete travel policy '$PolicyName': $($ErrorMessage.NormalizedError)" `
            -Sev 'Error' -tenant $TenantFilter -LogData $ErrorMessage
        throw "Failed to delete travel policy: $($ErrorMessage.NormalizedError)"
    }
}
