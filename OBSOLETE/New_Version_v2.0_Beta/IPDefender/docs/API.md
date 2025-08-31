# API Documentation for IPDefender

## Overview

IPDefender is a Python application designed to manage IP blocking and threat intelligence integration using Cloudflare, OTX (Open Threat Exchange), MISP (Malware Information Sharing Platform), and Wazuh. This document outlines the API endpoints available for interacting with the IPDefender application.

## Base URL

The base URL for the API is:

```
http://<your-server-address>/api
```

## Endpoints

### Block an IP

- **POST** `/block`
  
  Blocks a specified IP address.

  **Request Body:**
  ```json
  {
      "ip": "192.0.2.1"
  }
  ```

  **Response:**
  - **200 OK**: IP successfully blocked.
  - **400 Bad Request**: Invalid IP address format.
  - **404 Not Found**: IP already blocked.

### Unblock an IP

- **DELETE** `/unblock`
  
  Unblocks a specified IP address.

  **Request Body:**
  ```json
  {
      "ip": "192.0.2.1"
  }
  ```

  **Response:**
  - **200 OK**: IP successfully unblocked.
  - **404 Not Found**: IP not found in the block list.

### Fetch Threat Intelligence

- **GET** `/threats`
  
  Retrieves threat intelligence data from integrated sources.

  **Response:**
  - **200 OK**: Returns a list of threats.
  - **500 Internal Server Error**: Error fetching data from threat intelligence sources.

### List Blocked IPs

- **GET** `/blocked_ips`
  
  Retrieves a list of currently blocked IP addresses.

  **Response:**
  - **200 OK**: Returns a list of blocked IPs.
  - **500 Internal Server Error**: Error retrieving blocked IPs.

## Integration with Threat Intelligence Feeds

### OTX Integration

The application integrates with the OTX API to fetch threat data. Ensure you have your OTX API key configured in the application settings.

### MISP Integration

The application can also connect to a MISP instance to gather threat intelligence. Configuration for MISP should be set in the application settings.

### Wazuh Integration

Wazuh alerts can trigger IP bans based on detected threats. The application listens for alerts and processes them accordingly.

## Usage

To use the API, ensure you have the necessary authentication tokens and that your server is running. You can test the endpoints using tools like Postman or curl.

## Conclusion

This API documentation provides a comprehensive overview of the endpoints available in the IPDefender application. For further assistance, please refer to the setup and contributing documentation.