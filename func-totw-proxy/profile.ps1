# Azure Functions profile.ps1
# This profile runs on every cold start of the function app.

if ($env:MSI_SECRET) {
    Disable-AzContextAutosave -Scope Process | Out-Null
}
