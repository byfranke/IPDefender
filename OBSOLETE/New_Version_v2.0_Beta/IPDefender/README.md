# IPDefender

IPDefender is a Python-based application designed to enhance network security by blocking malicious IP addresses using the Cloudflare API. It integrates with various threat intelligence feeds, including OTX (Open Threat Exchange) and MISP (Malware Information Sharing Platform), and utilizes alerts from Wazuh to automate the banning of IPs based on detected threats.

## Features

- **IP Blocking**: Automatically block IP addresses based on threat intelligence and alerts from Wazuh.
- **Threat Intelligence Integration**: Fetch threat data from OTX and MISP to inform blocking decisions.
- **Wazuh Alerts**: Monitor Wazuh for security alerts and take action by banning malicious IPs.
- **Database Management**: Store and manage records of blocked IPs and associated threat data.
- **Web Interface**: A user-friendly web dashboard to monitor and manage blocked IPs and view threat intelligence.

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/IPDefender.git
   cd IPDefender
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Configure the application:
   - Copy `.env.example` to `.env` and fill in the required environment variables.
   - Update `config/config.yaml` with your specific configuration settings.

4. Run database migrations:
   ```
   python scripts/migrate.py
   ```

5. Start the application:
   ```
   python src/main.py
   ```

## Usage

To block an IP address:
```
python src/api/cloudflare.py add <IP_ADDRESS>
```

To unblock an IP address:
```
python src/api/cloudflare.py delete <IP_ADDRESS>
```

## Contributing

Contributions are welcome! Please read the [CONTRIBUTING.md](docs/CONTRIBUTING.md) for guidelines on how to contribute to the project.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Cloudflare API](https://api.cloudflare.com/)
- [OTX API](https://otx.alienvault.com/)
- [MISP API](https://www.misp-project.org/)
- [Wazuh](https://wazuh.com/) for security monitoring.