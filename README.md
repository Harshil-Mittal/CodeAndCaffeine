# CodeAndCaffeine
Web Deployment

## Backend Setup

1. Install dependencies:
   ```bash
   cd backend
   npm install
   ```
2. Create a `.env` file in the `backend` directory with the following (edit as needed):
   ```env
   JWT_SECRET=your_jwt_secret_here
   EMAIL_USER=harshilmittal2580@gmail.com
   EMAIL_PASS=fzpy kraf vick ftzq
   BASE_URL=http://localhost:3000
   ```
3. Start the backend server:
   ```bash
   npm start
   ```

## Features
- User sign up with email verification
- User sign in with JWT authentication
- SQLite database for user storage
