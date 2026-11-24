# Google Cloud Inspector: Setup Guide

## 1. Create a Google Cloud Service Account

1. Go to the [Google Cloud Console](https://console.cloud.google.com/).
2. Navigate to **IAM & Admin > Service Accounts**.
3. Click **Create Service Account**.
4. Enter a name (e.g., `inspector-sa`).
5. Click **Create and Continue**.
6. Grant the following roles:
   - `Viewer`
   - `Security Reviewer`
   - `Compute Viewer`
   - `Storage Admin`
   - `Kubernetes Engine Viewer`
   - `Service Account Token Creator`
7. Click **Done**.
8. Click the new service account, go to the **Keys** tab, and click **Add Key > Create new key**.
9. Choose **JSON** and download the key file. Keep it safe.

## 2. Running the Backend

1. Open a terminal and navigate to the project root.
2. Install dependencies:
   ```sh
   cd inspector-backend
   npm install
   ```
3. Start the backend server:
   ```sh
   npm run dev
   ```
   The backend will run on [http://localhost:4000](http://localhost:4000).

## 3. Running the Frontend

1. Open a new terminal window/tab.
2. Navigate to the frontend directory:
   ```sh
   cd inspector
   npm install
   ```
3. Start the frontend:
   ```sh
   npm run dev
   ```
   The frontend will run on [http://localhost:3000](http://localhost:3000) (or another port if 3000 is in use).

## 4. Using the App

1. Open the frontend in your browser.
2. Upload the downloaded service account JSON key when prompted.
3. Start scanning your Google Cloud project! 