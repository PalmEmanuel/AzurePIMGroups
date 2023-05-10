#Requires -Modules @{ ModuleName = 'Microsoft.Graph'; ModuleVersion = '1.27.0' }
#Requires -Modules @{ ModuleName = 'AzAuth'; ModuleVersion = '2.2.1' }
# Require modules with versions tested, might work with earlier versions
# https://api.azrbac.mspim.azure.com/api/v2/$metadata for endpoint information

function Register-PimAadGroup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Token,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$GroupId
    )

    $Headers = @{
        Authorization = "Bearer $Token"
    }

    # Register AAD Group in PIM
    $Body = @{ externalId = $GroupId } | ConvertTo-Json
    $ApiSplat = @{
        Method = 'Post'
        Headers = $Headers
        ContentType = 'application/json'
        Body = $Body
        Uri = 'https://api.azrbac.mspim.azure.com/api/v2/privilegedAccess/aadGroups/resources/register'
    }
    $null = Invoke-RestMethod @ApiSplat
}

function Get-PimGroupSettings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Token,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$GroupId
    )

    $Headers = @{
        Authorization = "Bearer $Token"
    }

    # Credits to https://github.com/ricmik/AzureAD-PrivilegedAccessGroups for inspiration
    # Get group Member and Owner objects in PIM settings
    Write-Output (Invoke-RestMethod -Uri "https://api.azrbac.mspim.azure.com/api/v2/privilegedAccess/aadGroups/roleSettingsv2?`$expand=roleDefinition(`$expand=resource)&`$filter=(resource/id+eq+'$GroupId')" -Headers $Headers).Value
}

function New-PimAadGroupRoleAssignment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Token,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId,
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$RoleDefinitionId,
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$GroupId,
        
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$State = 'Active',
        
        # The reason that will show up in the PIM role assignment
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Reason = "Created from script $(Get-Date -Format 'yyyy-MM-dd')"
    )

    $Headers = @{
        Authorization = "Bearer $Token"
    }

    $Body = @{
        resourceId       = $TenantId # The tenant is the resource to operate on
        roleDefinitionId = $RoleDefinitionId
        subjectId        = $GroupId
        assignmentState  = $State
        type             = 'AdminAdd'
        schedule         = @{
            type          = 'Once'
            startDateTime = Get-Date
            endDateTime   = $null
        }
        reason = $Reason # Reason is a required parameter when adding an active assignment, it's optional if eligible assignment
        # scopedResourceId = ''
        # condition = ''
        # conditionVersion = ''
    } | ConvertTo-Json
    Invoke-RestMethod -Uri 'https://api.azrbac.mspim.azure.com/api/v2/privilegedAccess/aadroles/roleAssignmentRequests' -Body $Body -Headers $Headers -Method Post -ContentType 'application/json'
}


function New-PIMGroupRoleAssignments {  
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TenantId,

        [Parameter()]
        [ValidateSet('All', 'BuiltIn', 'Custom')]
        [string]$RoleType = 'BuiltIn'
    )

    $TokenSplat = @{
        TenantId = $TenantId
        Interactive = $true
    }
    # Unfortunately we need to do two logins because we need tokens for two different clients
    # First get token for PIM using the Azure CLI Client Id
    $PimToken = Get-AzToken @TokenSplat -Resource 'https://api.azrbac.mspim.azure.com'
    # Then get token for Graph to use with Microsoft.Graph module commands, specifying scopes to handle Roles and Groups
    $GraphToken = Get-AzToken @TokenSplat -Resource 'https://graph.microsoft.com' -Scope 'RoleManagement.ReadWrite.Directory Group.ReadWrite.All' -ClientId '14d82eec-204b-4c2f-b7e8-296a70dab67e'
    Connect-MgGraph -AccessToken $GraphToken

    # Filter roles if not all
    if ($RoleType -eq 'All') {
        $Roles = Get-MgRoleManagementDirectoryRoleDefinition -All
    }
    else {
        # Get roles with filter "IsBuiltIn eq true" if BuiltIn is chosen as RoleType, otherwise "IsBuiltIn eq false"
        # Lowercase is important for the filter
        $Roles = Get-MgRoleManagementDirectoryRoleDefinition -Filter "IsBuiltIn eq $("$($RoleType -eq 'BuiltIn')".ToLower())"
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

        # TODO: Update settings of assignment
    }
}