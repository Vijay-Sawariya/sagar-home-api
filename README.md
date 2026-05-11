# Sagar Home LMS - Backend API

FastAPI backend for Sagar Home Lead Management System.

## Deployment to Railway

### Environment Variables Required:
```
MYSQL_HOST=your-mysql-host
MYSQL_PORT=3306
MYSQL_USER=your-username
MYSQL_PASSWORD=your-password
MYSQL_DATABASE=your-database
JWT_SECRET_KEY=your-jwt-secret
```

### Local Development
```bash
pip install -r requirements.txt
uvicorn server:app --reload --port 8001
```

## API Endpoints

- `POST /api/auth/login` - User login
- `GET /api/leads/clients` - Get client leads
- `GET /api/leads/inventory` - Get inventory leads
- `GET /api/dashboard/stats` - Dashboard statistics
- `GET /api/builders` - Get builders list
- `GET /api/health` - Health check
