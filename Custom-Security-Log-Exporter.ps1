# Custom Security Log Exporter
# Description: detailed script to export RDP failed login attempts from Windows Event Viewer (Event ID 4625)
#              and enrich them with Geolocation data using ipgeolocation.io API.


$API_KEY = "CHANGEME"
$LOGFILE_PATH = "C:\ProgramData\failed_rdp.log"

# Check if log file exists, create if not
if (-not (Test-Path $LOGFILE_PATH)) {
    New-Item -Path $LOGFILE_PATH -ItemType File | Out-Null
    Write-Host "Created log file at: $LOGFILE_PATH" -ForegroundColor Green
}

Write-Host "Starting Custom Security Log Exporter..." -ForegroundColor Cyan
Write-Host "Monitoring for Event ID 4625 (Failed RDP Logins)..." -ForegroundColor Cyan
Write-Host "Press Ctrl+C to stop."

# Infinite loop to monitor events
while ($true) {
    # Get the latest failed login events (Event ID 4625) from the last 1 second to avoid duplicates in this simple loop implementation
    # Note: In a production environment, you might use a more robust watermark method.
    $events = Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4625)]] and *[System[TimeCreated[timediff(@SystemTime) <= 2000]]]" -ErrorAction SilentlyContinue

    if ($events) {
        foreach ($event in $events) {
            # Extract IP Address from the event XML
            $xml = [xml]$event.ToXml()
            $ipAddress = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' } | Select-Object -ExpandProperty '#text'
            $timestamp = $event.TimeCreated

            # Skip internal IPs or empty IPs
            if ($ipAddress -ne "-" -and $ipAddress -ne $null -and $ipAddress -ne "") {
                
                # Check if we have already logged this specific event recently (optional basic dedup)
                # For this demo, we will just process it.

                Write-Host "Failed Login detected from IP: $ipAddress at $timestamp" -ForegroundColor Yellow
                
                # Get Geolocation Data
                try {
                    $geoUrl = "https://api.ipgeolocation.io/ipgeo?apiKey=$API_KEY&ip=$ipAddress"
                    $response = Invoke-RestMethod -Uri $geoUrl -Method Get
                    
                    # Extract fields
                    $latitude = $response.latitude
                    $longitude = $response.longitude
                    $country = $response.country_name
                    $city = $response.city
                    $state = $response.state_prov
                    
                    # Format log entry
                    # standardized format: latitude,longitude,destination_host,username,sourcehost,state,country,label,timestamp
                    # We will use a custom JSON format for better parsing in Sentinel, or raw CSV.
                    # Let's stick to the common format used in these labs:
                    # latitude,longitude,sourcehost,country,label,timestamp
                    
                    $logEntry = "$latitude,$longitude,$city,$country,$ipAddress,$timestamp"
                    
                    # Append to log file
                    Add-Content -Path $LOGFILE_PATH -Value $logEntry
                    
                    Write-Host "Logged: $logEntry" -ForegroundColor Magenta
                }
                catch {
                    Write-Host "Error retrieving Geolocation for IP $ipAddress : $_" -ForegroundColor Red
                }
            }
        }
    }
    # Wait for 1 second before polling again
    Start-Sleep -Seconds 1
}
