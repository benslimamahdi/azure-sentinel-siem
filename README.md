# Azure Sentinel SIEM - Honeypot Project

![Dashboard](dashboard%20screenshot.jpg)

## 🛡️ Introduction
This project demonstrates a cloud-based **Security Information and Event Management (SIEM)** system using **Microsoft Azure Sentinel**. 

I set up a **Windows 10 Virtual Machine (VM)** to act as a **Honeypot**, deliberately exposing it to the internet to attract potential attackers. Using a custom **PowerShell script**, I monitored RDP Brute Force attacks (Event ID 4625), extracted attacker IP addresses, and used a 3rd party API to geolocate them.

Finally, I ingested these logs into **Azure Log Analytics** and visualized the global attack data on a real-time **Azure Sentinel Map**.

## 🛠️ Tech Stack
- **Azure Sentinel (SIEM)**: For analyzing and visualizing the threat data.
- **Azure Log Analytics (LAW)**: To collect and query the logs.
- **Azure Virtual Machines**: Hosting the Windows 10 Honeypot.
- **PowerShell**: For extracting log data and interacting with the GeoIP API.
- **ipgeolocation.io API**: For converting IP addresses to physical locations.

## ⚙️ Architecture
1. **Attacker** tries to RDP into the Azure VM.
2. **Windows Event Viewer** records a failed login (Event ID 4625).
3. **PowerShell Script** polls these events, extracts the IP, and queries `ipgeolocation.io`.
4. **Custom Log** file (`failed_rdp.log`) is updated with Geo-data.
5. **Azure Log Analytics Agent** sends this custom log to the Workspace.
6. **Azure Sentinel** reads the data and plots it on the World Map.

## 🚀 Deployment Steps

### 1. Setup the Honeypot VM
1. Create a **Windows 10 Pro** VM in Azure.
2. **Networking**: Create a Network Security Group (NSG) rule allowing **All Traffic** (Inbound) on **All Ports**. 
    > ⚠️ **Warning**: This makes the VM extremely vulnerable. Do NOT use this on a production environment or an important account.
3. Log into the VM via RDP.
4. **Disable Firewall**: Turn off the Windows Firewall (Domain, Private, and Public profiles) to allow pings and discovery.

### 2. Run the PowerShell Script
1. Sign up for a free API key at [ipgeolocation.io](https://ipgeolocation.io/).
2. Open `Custom-Security-Log-Exporter.ps1` in PowerShell ISE on the VM.
3. Replace the `$API_KEY` variable with your own key.
4. Run the script. It will create logs at `C:\ProgramData\failed_rdp.log`.

![Terminal](terminal%20screenshot.jpg)

### 3. Configure Azure Sentinel
1. Create a **Log Analytics Workspace**.
2. Enable **Azure Sentinel** on that workspace.
3. **Data Connectors**: Connect the VM to the workspace.
4. **Custom Logs**: 
    - Configure the workspace to ingest the `C:\ProgramData\failed_rdp.log` file.
    - Create a Custom Log named `FAILED_RDP_WITH_GEO`.

### 4. Visualize Data (KQL)
Use the following KQL query in a Sentinel Workbook to map the data:

```kusto
FAILED_RDP_WITH_GEO_CL 
| extend username = extract(@"username:([^,]+)", 1, RawData),
         timestamp = extract(@"timestamp:([^,]+)", 1, RawData),
         latitude = extract(@"latitude:([^,]+)", 1, RawData),
         longitude = extract(@"longitude:([^,]+)", 1, RawData),
         sourcehost = extract(@"sourcehost:([^,]+)", 1, RawData),
         state = extract(@"state:([^,]+)", 1, RawData),
         label = extract(@"label:([^,]+)", 1, RawData),
         destination = extract(@"destinationhost:([^,]+)", 1, RawData)
| where destination != "samplehost"
| where sourcehost != ""
| summarize event_count=count() by sourcehost, latitude, longitude, country, label, destination
| render map
```

*(Note: The parsing logic depends on your specific log format in the script).*

## 📊 Results
The map below shows the global distribution of attackers trying to breach the honeypot within just a few hours of deployment.

![Logs](logs%20screenshot.jpg)

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
