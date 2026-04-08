using namespace System.Net

param($Request, $TriggerMetadata)

# BuckyComic Azure Function - Generates a Bucky comic strip via Gemini API
# Images are loaded from separate .txt files to avoid PowerShell parse errors
# with large inline base64 strings.

$ErrorActionPreference = 'Stop'

# --- Load base64 image data from external files ---
$functionRoot = $PSScriptRoot

try {
    $buckyFrontB64 = (Get-Content -Path (Join-Path $functionRoot 'bucky_front_b64.txt') -Raw).Trim()
    $buckyFullB64  = (Get-Content -Path (Join-Path $functionRoot 'bucky_full_b64.txt') -Raw).Trim()
    $buckyHeadB64  = (Get-Content -Path (Join-Path $functionRoot 'bucky_head_b64.txt') -Raw).Trim()
}
catch {
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::InternalServerError
        Headers    = @{ 'Content-Type' = 'application/json' }
        Body       = (@{ error = "Failed to load image files: $($_.Exception.Message)" } | ConvertTo-Json)
    })
    return
}

# --- Get Gemini API key from environment ---
$geminiApiKey = $env:GEMINI_API_KEY
if (-not $geminiApiKey) {
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::InternalServerError
        Headers    = @{ 'Content-Type' = 'application/json' }
        Body       = (@{ error = 'GEMINI_API_KEY environment variable is not set' } | ConvertTo-Json)
    })
    return
}

# --- Parse request body ---
$requestBody = $null
if ($Request.Body) {
    $requestBody = $Request.Body
}

$tipText = $requestBody.tip
$panelCount = if ($requestBody.panels) { [int]$requestBody.panels } else { 4 }

if (-not $tipText) {
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::BadRequest
        Headers    = @{ 'Content-Type' = 'application/json' }
        Body       = (@{ error = 'Missing required field: tip' } | ConvertTo-Json)
    })
    return
}

# --- Build Gemini API request ---
$geminiUrl = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=$geminiApiKey"

$systemPrompt = @"
You are a comic strip writer for Barry University's AI Tip of the Week newsletter.
The mascot is Bucky the Buccaneer. Create a $panelCount-panel comic strip script that illustrates the following AI tip in a fun, relatable way for university staff and faculty.

Each panel should have:
- A scene description (what is visually happening)
- Dialogue for the characters (keep it short and punchy)
- Which version of Bucky to use: front (standing facing viewer), full (full body action pose), or head (close-up headshot)

Make it funny, warm, and educational. The comic should make the AI tip memorable and approachable.
"@

$payload = @{
    contents = @(
        @{
            role = 'user'
            parts = @(
                @{
                    inlineData = @{
                        mimeType = 'image/png'
                        data     = $buckyFrontB64
                    }
                }
                @{
                    inlineData = @{
                        mimeType = 'image/png'
                        data     = $buckyFullB64
                    }
                }
                @{
                    inlineData = @{
                        mimeType = 'image/png'
                        data     = $buckyHeadB64
                    }
                }
                @{
                    text = "$systemPrompt`n`nHere is the AI tip to illustrate:`n`n$tipText"
                }
            )
        }
    )
    generationConfig = @{
        temperature  = 0.9
        maxOutputTokens = 2048
    }
} | ConvertTo-Json -Depth 10

# --- Call Gemini API ---
try {
    $headers = @{ 'Content-Type' = 'application/json' }
    $geminiResponse = Invoke-RestMethod -Uri $geminiUrl -Method Post -Headers $headers -Body $payload -TimeoutSec 60

    $comicScript = $geminiResponse.candidates[0].content.parts[0].text

    $responseBody = @{
        success = $true
        comic   = $comicScript
        panels  = $panelCount
        tip     = $tipText
    } | ConvertTo-Json -Depth 5

    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Headers    = @{ 'Content-Type' = 'application/json' }
        Body       = $responseBody
    })
}
catch {
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::BadGateway
        Headers    = @{ 'Content-Type' = 'application/json' }
        Body       = (@{
            error   = "Gemini API call failed: $($_.Exception.Message)"
            details = $_.ErrorDetails.Message
        } | ConvertTo-Json)
    })
}
