# Google Cloud Inspector

A web application that inspects Google Cloud assets from security and architecture perspectives.

## Features

- Connect to cloud projects via a service account with viewer permissions
- Perform security and compliance checks on various GCP services
- Score projects based on security best practices
- Identify and alert on potential security issues

## Services Supported

- Compute Engine
- Cloud Storage
- Cloud Run
- VPC
- More to be added

## Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   npm install
   ```
3. Start development server:
   ```bash
   npm run dev
   ```

## Build for Production

```bash
npm run build
```

## Project Structure

- `/src/components` - Reusable UI components
- `/src/pages` - Main application pages
- `/src/services` - Services for interacting with GCP APIs
- `/src/utils` - Utility functions and helpers
- `/src/hooks` - Custom React hooks

## Scoring Algorithm

The application implements a simple binary scoring system:
- 1 point if a check passes
- 0 if it fails
- Final project score calculated out of 100

## Service Account Setup

To use this application, you'll need a Google Cloud service account with the following permissions:
- Compute Viewer
- Storage Viewer
- VPC Network Viewer
- Cloud Run Viewer
- Other service-specific viewer roles as needed

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the ISC License. 