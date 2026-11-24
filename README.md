# Google Cloud Inspector

Google Cloud Inspector is a web-based tool for scanning Google Cloud Platform (GCP) projects for security risks, misconfigurations, and best practice violations. It provides a detailed compliance report and PDF export for your GCP resources.

## Features
- Scan Compute Engine, Cloud Storage, Kubernetes Engine, IAM, and VPC
- Detailed security checks and recommendations
- PDF export of compliance reports
- Modern, easy-to-use UI

## Setup
1. **Clone the repository:**
   ```bash
   git clone <your-bitbucket-repo-url>
   cd inspector
   ```
2. **Install dependencies:**
   ```bash
   cd inspector && npm install
   cd ../inspector-backend && npm install
   ```
3. **Run the app:**
   - Start the backend:
     ```bash
     cd inspector-backend && node server.js
     ```
   - Start the frontend:
     ```bash
     cd inspector && npm run dev
     ```
   - Open [http://localhost:3000](http://localhost:3000) in your browser.

## Usage
- Upload a GCP service account key (with at least Viewer permissions) to scan your project. (For organization node you need both browser and viewer)
- View detailed results and download a PDF report.
---

*For more details, see the code and comments in each directory.* 