# AzureAD-CheckInactiveUsersAndDevices
~~Note: Requires AzureAD Premium license (P1 or P2) for AuditSignInLogs in Preview version of AzureAD~~
Script has been converted to utilise Microsoft Graph REST API - I don't know if it requires specific licensing.

Optionally include the .bat file in same directory as the .ps1 file for easy run-as-admin.
Admin is only required for module installation so if module is already in order (i.e. by a previous run) it's sufficient to just run script directly in non-admin context.
