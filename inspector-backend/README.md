# Google Cloud Inspector Backend

This is the backend service for the Google Cloud Inspector application, which provides real GCP API integration for security compliance scanning.

## Features

- Secure handling of GCP service account credentials
- Real API calls to Google Cloud services
- Implementation of all 15 Compute Engine security checks
- Implementation of all 9 Cloud Storage security checks
- RESTful API for frontend integration

## Prerequisites

- Node.js 14 or higher
- npm or yarn

## Installation

```bash
npm install
```

## Configuration

No additional configuration is needed. The service accepts GCP service account credentials from the frontend.

## Running the Service

Development mode:

```bash
npm run dev
```

Production mode:

```bash
npm start
```

## API Endpoints

### Authentication

```
POST /api/authenticate
```

Request body:
```json
{
  "serviceAccountKey": {
    "project_id": "your-project-id",
    "client_email": "your-service-account@your-project-id.iam.gserviceaccount.com",
    "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
  }
}
```

Response:
```json
{
  "success": true
}
```

### Scan Project

```
POST /api/scan
```

Request body:
```json
{
  "serviceAccountKey": {
    "project_id": "your-project-id",
    "client_email": "your-service-account@your-project-id.iam.gserviceaccount.com",
    "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
  }
}
```

Response:
```json
{
  "projectId": "your-project-id",
  "projectName": "your-project-id (All-In-Cloud Scan)",
  "score": 85,
  "services": [
    {
      "id": "compute-engine",
      "name": "Compute Engine",
      "score": 80,
      "checks": [...]
    },
    {
      "id": "cloud-storage",
      "name": "Cloud Storage",
      "score": 90,
      "checks": [...]
    }
  ]
}
```

## Security Considerations

This service handles sensitive GCP service account keys. In a production environment:

1. Implement proper authentication for API access
2. Use HTTPS for all communications
3. Consider implementing session management with secure tokens
4. Don't store service account keys persistently
5. Use environment variables for configuration

## Deployment

For production deployment, consider using:

- Google Cloud Run
- Google App Engine
- Docker with Kubernetes 