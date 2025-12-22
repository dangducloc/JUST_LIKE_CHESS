### Chess.com wannabe
A real-time online chess application built with Python (Flask) and WebSockets, featuring matchmaking and AI gameplay.

## 🚀 Key Features
- PvP Mode: Real-time matches with other players using an ELO-based matchmaking system.

- PvE Mode: Challenge the computer powered by the Stockfish engine with multiple difficulty levels.

- Game Analysis: Review finished matches with move-by-move evaluation (Inaccuracies, Mistakes, Blunders).

- User System: Secure authentication (JWT), email confirmation, and global ELO leaderboards.

## 🛠 Tech Stack
> Backend: Flask, Flask-SocketIO (WebSocket), JWT.

> Database: MongoDB (User data, Match history, and Queues).

> Engine: Stockfish (AI logic and game analysis).

> Frontend: HTML5, CSS3, JavaScript (Vanilla), Chessboard.js.

## 📂 Project Structure
- /api: REST API endpoints for authentication, matchmaking, and reviews.

- /controllers: Core business logic for bot behavior and match management.

- /web_socket: Real-time communication handlers for PvP and PvE sessions.

- /static & /templates: Frontend assets and UI components.

## ⚙️ Quick Start
- Environment: Create a .env file with SECRET_KEY, MAIL_USERNAME, APP_PASS, MONGO_URI, and STOCKFISH_PATH.

- Install: `Run pip install -r requirements.txt.`

- Run: Execute python web.py.

- Access the app at http://localhost:5000.