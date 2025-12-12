# BayGuard UI

This directory contains a lightweight, static demo console for BayGuard that you can host via **AWS Amplify**.

The UI is a single-page HTML/JS app that can:

- Trigger scans via `POST /scan`
- Generate reports via `POST /report`
- Call the AI orchestrator via `POST /ai/explain`

It talks directly to the BayGuard HTTP API exposed by API Gateway (for example: `https://bayguard.bayareala8s.com`).

## Files

- `index.html` – main single-page app with inline JavaScript.

## Local Usage (Quick Check)

You can quickly open the UI locally just to see it:

1. Ensure your BayGuard backend is deployed (see `infra/README.md`).
2. Open `ui/index.html` directly in your browser (double-click in Finder or use `open ui/index.html`).
3. In the **API Base URL** field, enter your API base, for example:

	- `https://bayguard.bayareala8s.com`
	- Or the raw `http_api_url` Terraform output.

Because the HTTP API has CORS enabled, browser calls from this page will succeed as long as the API URL is reachable.

## Deploying the UI with AWS Amplify

You can host this static UI using **Amplify Hosting**.

### Option A – Connect a Git Repository

1. Push this repo to GitHub/GitLab/CodeCommit.
2. In the AWS Console, go to **AWS Amplify → Hosting → New app → Host web app**.
3. Select your Git provider and choose the repository containing this project.
4. When asked for build settings:
	- Framework: **Static web hosting** (or "None" / "Custom" if prompted).
	- Build command: leave empty.
	- Output directory: set to `ui`.
5. Save and deploy.

Amplify will serve `ui/index.html` at a URL like:

- `https://main.xxxxxx.amplifyapp.com`

In the page, set the **API Base URL** to your BayGuard API endpoint (`https://bayguard.bayareala8s.com`).

### Option B – Drag-and-Drop Deployment

1. Build an artifact by zipping the contents of the `ui` directory:

	```bash
	cd ui
	zip -r bayguard-ui.zip .
	```

2. In the AWS Console, go to **AWS Amplify → Hosting → Get started → Deploy without Git provider**.
3. Drag and drop `bayguard-ui.zip`.
4. Once deployed, open the Amplify URL it provides.
5. Set the **API Base URL** field to your BayGuard API endpoint.

## Demo Flow

After the UI is live on Amplify and your backend is deployed:

1. Open the Amplify URL in your browser.
2. Set **API Base URL** to `https://bayguard.bayareala8s.com` (or your equivalent custom domain).
3. Click **Run Scan** to trigger a new scan and show the JSON response.
4. Click **Generate Report (Latest Scan)** to create an HTML report in S3 (the response includes the S3 URL).
5. Use **AI Explanation** to show persona-based explanations (`developer`, `architect`, `executive`) for a sample finding.

This gives you a clean, browser-based demo of BayGuard without needing CLI tools in front of customers.
