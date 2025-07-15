# Web Crawler Project

A web app that explores websites to find links and analyze content, built as a technical demonstration.

## What It Does

- **Explores websites** discovering all pages and links
- **Checks for problems** like broken links or missing information
- **Shows website details**: page structure, login forms, and content organization
- **Updates in real-time** as it works



### Backend (Go code)
- Handles website exploration
- Stores results in database
- Runs in Docker containers

### Frontend (React App)
- Shows results in dashboard
- Clean, mobile-friendly interface
- Real-time updates

## Key Features

### Exploration Tools
- Finds all links on websites
- Checks which links work or are broken
- Counts headings (H1-H6 tags)
- Detects login forms
- Shows progress (waiting → working → done)

### User Interface
- Clean dashboard with stats
- Works on phones and computers
- Search and filter results
- Detailed page analysis
- Bulk actions (delete/retry multiple sites)

### Technical Details
- Secure login system
- Automatic updates
- Handles multiple sites at once
- Error messages when things go wrong
- Runs in containers for easy setup

## Get Started

### You'll Need
- Docker (with Docker Compose)
- Node.js 18+ (for frontend)
- Go 1.21+ (for backend)

### Setup Steps

1. **Get the code**  
   ```bash
   git clone https://github.com/Raven1233/web-crawler.git
   cd web-crawler```

2. **Start Backend server**
    ```bash
    cd backend
    docker-compose up -d```

3. **Start Frontend**
    ```bash
    cd ../frontend
    npm install
    npm run dev```

4. **Open the app**
    - Visit http://localhost:8081 and login with:
    - Username: admin
    - Password: password

### Built by Subhadeep Das