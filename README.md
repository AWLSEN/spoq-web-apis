# SPOQ Web APIs

A high-performance Rust-based web API service built with Actix-web, designed for deployment on Railway.

## Overview

SPOQ Web APIs provides a robust backend service with GitHub OAuth authentication, database integration via PostgreSQL, and modern security features including JWT authentication and rate limiting.

## Features

- Built with Actix-web 4.x for high performance
- PostgreSQL database integration with SQLx
- GitHub OAuth authentication
- JWT-based session management
- Rate limiting with actix-governor
- Structured logging with tracing
- Multi-stage Docker builds for optimized deployment
- Railway-ready configuration

## Tech Stack

- **Framework**: Actix-web 4.12
- **Database**: PostgreSQL (via SQLx 0.8)
- **Auth**: GitHub OAuth + JWT (jsonwebtoken 9)
- **Security**: Argon2 password hashing, rate limiting
- **HTTP Client**: Reqwest 0.12 with rustls
- **Runtime**: Tokio 1.49
- **Observability**: Tracing + tracing-subscriber

## Local Development Setup

### Prerequisites

- Rust 1.84 or later
- PostgreSQL 14 or later
- GitHub OAuth App (for authentication)

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd spoq-web-apis
```

2. Set up environment variables:
```bash
cp .env.example .env
```

Edit `.env` with your configuration:
```env
# Database Configuration
DATABASE_URL=postgres://user:pass@localhost:5432/spoq

# GitHub OAuth Configuration
GITHUB_CLIENT_ID=your_client_id
GITHUB_CLIENT_SECRET=your_client_secret
GITHUB_REDIRECT_URI=http://localhost:8080/auth/github/callback

# JWT Configuration
JWT_SECRET=your_jwt_secret_min_32_chars

# Server Configuration
HOST=0.0.0.0
PORT=8080
```

3. Set up the database:
```bash
# Create database
createdb spoq

# Run migrations (if available)
sqlx migrate run
```

4. Build and run:
```bash
cargo build --release
cargo run
```

The API will be available at `http://localhost:8080`

## Railway Deployment

### Step 1: Create Railway Project

1. Go to [Railway](https://railway.app) and create a new project
2. Choose "Deploy from GitHub repo" or use Railway CLI

### Step 2: Add PostgreSQL Database

1. In your Railway project dashboard, click "New"
2. Select "Database" → "Add PostgreSQL"
3. Railway will automatically create a PostgreSQL instance and set `DATABASE_URL`

### Step 3: Configure Environment Variables

Add the following environment variables in Railway's dashboard:

| Variable | Description | Example |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | Auto-set by Railway Postgres plugin |
| `GITHUB_CLIENT_ID` | GitHub OAuth App Client ID | `abc123def456` |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth App Secret | `secret_xyz789` |
| `GITHUB_REDIRECT_URI` | OAuth callback URL | `https://your-app.railway.app/auth/github/callback` |
| `JWT_SECRET` | Secret for JWT signing (32+ chars) | `your-secure-random-string-min-32-chars` |
| `HOST` | Server host | `0.0.0.0` |
| `PORT` | Server port | `8080` |

### Step 4: Deploy

#### Option A: Deploy from GitHub

1. Connect your GitHub repository to Railway
2. Railway will automatically detect the Dockerfile
3. Push to your main branch to trigger deployment

#### Option B: Deploy using Railway CLI

```bash
# Install Railway CLI
npm i -g @railway/cli

# Login
railway login

# Link to project
railway link

# Deploy
railway up
```

### Step 5: Verify Deployment

Once deployed, Railway will provide a public URL (e.g., `https://your-app.railway.app`). Test the deployment:

```bash
curl https://your-app.railway.app/
# Expected: "Hello, World!"
```

## GitHub OAuth Setup

To enable GitHub authentication, you need to create a GitHub OAuth App:

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Click "New OAuth App"
3. Fill in the details:
   - **Application name**: SPOQ Web APIs
   - **Homepage URL**: Your Railway app URL or `http://localhost:8080` for development
   - **Authorization callback URL**: `https://your-app.railway.app/auth/github/callback`
4. Click "Register application"
5. Copy the **Client ID** and generate a **Client Secret**
6. Add these to your Railway environment variables or local `.env` file

## API Endpoints

### Health Check
- **GET** `/` - Returns "Hello, World!" (used for health checks)

### Authentication (Coming Soon)
- **GET** `/auth/github` - Initiate GitHub OAuth flow
- **GET** `/auth/github/callback` - OAuth callback handler
- **POST** `/auth/logout` - Logout user

### Protected Routes (Coming Soon)
- All authenticated routes require `Authorization: Bearer <jwt_token>` header

## Project Structure

```
spoq-web-apis/
├── src/
│   └── main.rs           # Application entry point
├── Cargo.toml            # Rust dependencies
├── Dockerfile            # Multi-stage Docker build
├── railway.toml          # Railway configuration
├── .env.example          # Environment variables template
└── README.md             # This file
```

## Development

### Running Tests

```bash
cargo test
```

### Building for Production

```bash
cargo build --release
```

The optimized binary will be in `target/release/spoq-web-apis`

### Docker Build (Local)

```bash
# Build image
docker build -t spoq-web-apis .

# Run container
docker run -p 8080:8080 --env-file .env spoq-web-apis
```

## Configuration

### Environment Variables

All configuration is done via environment variables. See `.env.example` for a complete list.

### Railway-Specific Configuration

The `railway.toml` file configures deployment behavior:
- Dockerfile-based builds
- Health check on `/` endpoint
- 30-second health check timeout
- Automatic restart on failure (max 3 retries)

## Security Considerations

1. **JWT Secret**: Use a strong, random secret (32+ characters)
2. **HTTPS**: Always use HTTPS in production (Railway provides this automatically)
3. **Environment Variables**: Never commit `.env` files or secrets to git
4. **Rate Limiting**: Built-in rate limiting to prevent abuse
5. **Password Hashing**: Argon2 for secure password storage

## Troubleshooting

### Port Issues
Railway automatically assigns a `PORT` environment variable. The app is configured to use port 8080 by default.

### Database Connection
Ensure `DATABASE_URL` is properly set. Railway's PostgreSQL plugin sets this automatically.

### Build Failures
Check Railway build logs. Common issues:
- Missing dependencies in Dockerfile
- Cargo.lock conflicts (delete and rebuild)
- Out of memory (increase Railway plan)

### Health Check Failures
The health check pings `/` endpoint. Ensure:
- App starts within 30 seconds
- Port 8080 is exposed
- No blocking operations in startup

## License

MIT

## Support

For issues and questions, please open an issue on GitHub.
