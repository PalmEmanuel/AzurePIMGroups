[CmdletBinding(DefaultParameterSetName = 'RoleType')]
param(
    [Parameter(Mandatory, ParameterSetName = 'RoleType')]
    [Parameter(Mandatory, ParameterSetName = 'Csv')]
    [string]$TenantId,

    [Parameter(ParameterSetName = 'RoleType')]
    [ValidateSet('All', 'BuiltIn', 'Custom')]
    [string]$RoleType = 'BuiltIn',

    [Parameter(Mandatory, ParameterSetName = 'Csv')]
    [ValidateScript({ if (-not (Test-Path $_)) { throw "Specified path '$_' does not exist!" } })]
    [string]$CsvFilePath
)

Import-Module .\AzurePimGroups.psm1

$TokenSplat = @{
    TenantId    = $TenantId
    Interactive = $true
}
# Unfortunately we need to do two logins because we need tokens for two different clients
# First get token for PIM using the Azure CLI Client Id
$PimToken = Get-AzToken @TokenSplat -Resource 'https://api.azrbac.mspim.azure.com'
# Then get token for Graph to use with Microsoft.Graph module commands, specifying scopes to handle Roles and Groups
$GraphToken = Get-AzToken @TokenSplat -Resource 'https://graph.microsoft.com' -Scope 'RoleManagement.ReadWrite.Directory Group.ReadWrite.All' -ClientId '14d82eec-204b-4c2f-b7e8-296a70dab67e'
Connect-MgGraph -AccessToken $GraphToken

switch ($PSCmdlet.ParameterSetName) {
    'Csv' {
        $CsvContent = Import-Csv $CsvFilePath -Delimiter ';' -Encoding utf8 # semi-colon is used by Excel on Swedish computers
        # Get all role definitions in CSV from Graph, for description etc
        $Roles = foreach ($CsvRole in $CsvContent) {
            try {
                $Role = Get-MgRoleManagementDirectoryRoleDefinition -Filter "Id eq '$($CsvRole.Id)'" -ErrorAction Stop
                Write-Output $Role
            }
            catch {
                Write-Error -Exception $_.Exception -Message "Could not get role '$($CsvRole.DisplayName)' by id '$($CsvRole.Id)'!"
            }
        }
    }
    'RoleType' {
        # Filter roles if not all
        if ($RoleType -eq 'All') {
            $Roles = Get-MgRoleManagementDirectoryRoleDefinition -All
        }
        else {
            # Get roles with filter "IsBuiltIn eq true" if BuiltIn is chosen as RoleType, otherwise "IsBuiltIn eq false"
            # Lowercase is important for the filter
            $Roles = Get-MgRoleManagementDirectoryRoleDefinition -Filter "IsBuiltIn eq $("$($RoleType -eq 'BuiltIn')".ToLower())"
        }
    }
    default { throw 'Invalid parameter set!' }
}

foreach ($Role in $Roles) {
    # If group was created by this script before, don't create a new one
    $ExistingGroup = Get-MgGroup -Filter "mailNickname eq 'pim-$($Role.Id)'"
    if ($null -ne $ExistingGroup) {
        continue
    }

    $GroupSplat = @{
        DisplayName        = "PIM $($Role.DisplayName)"
        Description        = "The PIM assignment group for the role $($Role.DisplayName). $($Role.Description)"
        SecurityEnabled    = $true
        IsAssignableToRole = $true
        MailEnabled        = $false
        MailNickname       = "pim-$($Role.Id)"
    }
    $Group = New-MgGroup @GroupSplat
        
    # Register the created group in PIM
    Register-PimAadGroup -Token $PimToken -GroupId $Group.Id

    # Create active PIM role assignment for the created AAD group
    $null = New-PimAadGroupRoleAssignment -Token $PimToken -TenantId $TenantId -RoleDefinitionId $Role.Id -GroupId $Group.Id -State 'Active'

    # Update PIM activation settings for non-admins in Member role
    Update-PimAadGroupRoleSettings -Token $PimToken -RoleId $Role.Id -RoleType Member -SettingType Assignment -User EndUser -GroupId $Group.Id -Rule @(
            (New-PimAadGroupRoleSettingRuleObject -ExpirationRule -ExpirationTime ([timespan]::FromHours(8)))
            (New-PimAadGroupRoleSettingRuleObject -MfaRule -MfaRequired $true) # MFA required
            (New-PimAadGroupRoleSettingRuleObject -JustificationRule -JustificationRequired $true) # Justification required
            (New-PimAadGroupRoleSettingRuleObject -TicketingRule -TicketingRequired $false) # No ticketing
            (New-PimAadGroupRoleSettingRuleObject -AcrsRule -AcrsRequired $false -Acrs '') # Empty ACRS rule
            (New-PimAadGroupRoleSettingRuleObject -ApprovalRule -ApprovalEnabled $false -Approvers (@())) # No approvers
            (New-PimAadGroupRoleSettingRuleObject -NotificationRule) # Default notification rule
    )
}