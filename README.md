# Create PIM Assignments

A module with functionality to create and register AAD groups to PIM, and to assign defined roles in AAD.

Example script `CreatePimAssignments.ps1` which uses the module.

```PowerShell
Install-Module Microsoft.Graph
Install-Module AzAuth

CreatePimAssignments.ps1 -TenantId '2b90b434-12a6-4d57-a6a0-f466485ac355'
```

The script logs in twice to get different tokens, might be improved in the future.