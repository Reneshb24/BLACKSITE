
# AEGIS BLACKSITE – AUTHORIZATION & SECURITY ASSESSMENT PLATFORM

Aegis Blacksite is a specialized web security target and sandboxed authentication gateway designed for security analysts, penetration testers, and ethical hackers to practice vulnerability assessment, client-side reverse engineering, and access control testing.

Web security testing often suffers from either overly theoretical concepts or live targets where testing is restricted or dangerous. Aegis Blacksite provides an isolated, realistic, and controlled environment modeling an enterprise-grade defense or military authorization node (`AEGIS BLACKSITE // AUTHORIZATION NETWORK`).

The application features an industrial terminal-style interface, dynamic authorization validation, client-side bundle structures, and serverless API route handlers. Users analyze the authentication flow, intercept and inspect HTTP traffic, audit client-side JavaScript assets for hidden logic, and craft payloads to bypass authentication barriers and retrieve authorized flags or access states.

## The Problem

Modern web applications frequently suffer from critical security flaws, particularly in client-side state handling and authentication logic.

Common issues encountered in modern applications include:

-   Trusting client-side validation without proper server-side verification.
    
-   Leaking internal route structures, API keys, or logic in unminified/unstripped production JavaScript chunks.
    
-   Insecure Direct Object References (IDOR) on privileged dashboard endpoints.
    
-   Vulnerable authentication mechanics susceptible to query injection or parameter tampering.
    
-   Missing rate-limiting and improper session/token state management.
    
-   Lack of hands-on, zero-risk environments where security researchers can safely test and analyze these attack vectors end-to-end.
    

Aegis Blacksite solves this by providing a dedicated, fully self-contained security target with real-world architectural patterns.

## Why Aegis Blacksite?

Aegis Blacksite is designed specifically for cybersecurity learners, CTF researchers, and web application security auditors.

Instead of reading about vulnerabilities abstractly, users interact directly with a live target:

-   Inspect production Webpack/Next.js client-side bundles.
    
-   Analyze and intercept real-time HTTP authentication requests.
    
-   Test authentication routines using proxies like Burp Suite or OWASP ZAP.
    
-   Practice input manipulation, parameter pollution, and logic bypasses.
    
-   Understand how developers unintentionally expose sensitive operational paths in single-page applications.
    
-   Learn defensive remediation strategies to properly patch web vulnerabilities.
    

The primary goal of the application is to bridge the gap between web application development and practical cybersecurity auditing.

## Key Features

### 1. Cyber Gateway Authentication Interface

The application presents an industrial, dark-themed security access portal (`/login`) simulating a restricted authorization node. It captures user inputs and routes them through a structured authentication pipeline.

### 2. Client-Side Chunk & Route Architecture

Built on a modern React/Next.js framework, the frontend compiles into modular static assets. Researchers can evaluate how routes, endpoints, and component states are packaged in production environments.

### 3. Serverless API Route Handlers

The platform utilizes serverless endpoint handlers to process authentication payloads, execute validation checks, and manage response status headers (`200 OK`, `401 Unauthorized`, `500 Internal Error`).

### 4. Interception-Ready Network Flow

Every client action generates inspectable network traffic, allowing researchers to study request headers, cookies, query parameters, and JSON payloads via standard developer tools or HTTP proxies.

### 5. Configurable Payload & Input Surface

Input fields accept standard and malformed payloads, making it an ideal environment for testing SQLi, NoSQLi, parameter pollution, and authentication bypass strings.

### 6. Realistic Feedback States

The portal returns clear, distinct feedback across access-denied, invalid token, and successful authorization transitions, aiding in structured security documentation and report writing.

## Technology Stack

-   **Frontend Framework:** Next.js (React)
    
-   **Deployment Platform:** Vercel (Edge & Serverless Infrastructure)
    
-   **Styling:** Tailwind CSS / Custom Cyber Terminal Theme
    
-   **Target Surface:** Web Authentication Gateway (`/login`)
    
-   **Version Control:** Git and GitHub
    
-   **Libraries and Dependencies:**
    
    -   `react` – Component-based UI engine
        
    -   `react-dom` – DOM rendering layer for React
        
    -   `next` – Fullstack React framework with SSR and API routes
        
    -   `tailwindcss` – Utility-first CSS styling for interface theming
        
    -   `lucide-react` – Clean, modern UI iconography
        

## Project Structure

```
blacksite/
├── pages/ or app/         # Application routing and view components
│   ├── api/               # Serverless backend API route handlers
│   │   └── auth/          # Authentication & verification logic
│   ├── login/             # Main Aegis Blacksite login portal
│   └── _app.js / layout.js# Global providers and core layout wrapper
├── public/                # Static assets, icons, and public challenge files
├── styles/                # Global CSS styles and Tailwind configurations
├── components/            # Reusable UI components (terminal boxes, status badges)
├── package.json           # Project dependencies, scripts, and build commands
├── next.config.js         # Next.js configuration file
└── tailwind.config.js     # Styling configuration and custom dark/cyber theme

```

## Target Workflow & Analysis Methodology

### Phase 1: Passive Reconnaissance & Source Inspection

1.  Navigate to the live instance: `[https://blacksite-bugbounty.vercel.app/login](https://blacksite-bugbounty.vercel.app/login)`.
    
2.  Inspect the raw source code and developer tools (`F12`).
    
3.  Traverse the **Sources / Network** tabs to review loaded JavaScript bundles (`_next/static/chunks/`):
    
    -   Identify internal API paths (e.g., `/api/*`, `/dashboard`, `/admin`).
        
    -   Look for hardcoded validation functions, comments, or residual developer objects.
        

### Phase 2: Traffic Interception & Payload Crafting

1.  Set up an HTTP proxy (e.g., Burp Suite or OWASP ZAP) or use the browser Network tab.
    
2.  Submit a test authentication attempt through the interface.
    
3.  Intercept the request to examine:
    
    -   Target HTTP method (`POST`) and Content-Type (`application/json` or form-data).
        
    -   Parameters passed in the payload body.
        
    -   Headers and cookie structures.
        

### Phase 3: Fuzzing & Exploitation

1.  Send payloads to the endpoint via proxy repeater or `curl`.
    
2.  Test for common bypass strings:
    
    Plaintext
    
    ```
    admin' --
    admin' OR '1'='1
    {"username": "admin", "password": {"$ne": null}}
    
    ```
    
3.  Test parameter alteration, type confusion (sending JSON booleans/arrays), and direct access to protected routes.
    

## Setup and Installation Guide

To run Aegis Blacksite locally for inspection and testing:

### 1. Prerequisites

Before starting, ensure your system has the following installed:

-   **Git:** [https://git-scm.com/downloads](https://git-scm.com/downloads)
    
-   **Node.js (v18.x or higher):** [https://nodejs.org/](https://nodejs.org/)
    
-   **Package Manager:** `npm` (bundled with Node.js), `yarn`, or `pnpm`
    

Verify installation:

Bash

```
node -v
npm -v
git --version

```

### 2. Clone the Repository

Bash

```
git clone https://github.com/Reneshb24/blacksite.git
cd blacksite

```

### 3. Install Dependencies

Bash

```
npm install
# or
yarn install
# or
pnpm install

```

### 4. Run the Development Server

Bash

```
npm run dev
# or
yarn dev

```

Open [http://localhost:3000](http://localhost:3000) in your browser to view the application.

## Recommended Security Tooling

-   **HTTP Proxies:** Burp Suite Community/Pro, OWASP ZAP, Caido
    
-   **CLI & Automation:** `curl`, `httpie`, Python (`requests` module)
    
-   **Decoding & Inspection:** CyberChef, JWT.io
    
-   **Source Map Utilities:** Browser DevTools, `shuji`, or Webpack unpackers
    


## Future Improvements

-   Multi-stage CTF flags with progressive challenge unlocking.
    
-   Automated rate-limiting and intrusion detection challenge layers.
    
-   Admin dashboard interface with simulated role-based access control (RBAC).
    
-   Interactive hint and solution verification engine.
    

## Author

Renesh B ([@Reneshb24](https://www.google.com/search?q=https://github.com/Reneshb24))

_Disclaimer: This platform is designed solely for defensive security analysis, educational exercises, and authorized vulnerability assessment. Do not execute unauthorized attacks against systems without explicit permission._
