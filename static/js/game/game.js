// ==================== GAME STATE ====================
let socket = null;
let game = null;
let board = null;
let matchId = null;
let userId = null;
let playerColor = null;
let opponentColor = null;
let isMyTurn = false;
let gameActive = true;

// Reconnection
let reconnectAttempts = 0;
const MAX_RECONNECT_ATTEMPTS = 5;
const RECONNECT_DELAY = 2000;

// ==================== INITIALIZATION ====================
document.addEventListener('DOMContentLoaded', async () => {
    matchId = document.getElementById('matchId').value;
    
    // Hide loading after init
    setTimeout(() => {
        document.getElementById('loadingOverlay').classList.add('hidden');
    }, 1000);
    
    // Get user info
    await loadUserInfo();
    
    // Initialize Socket.IO
    initializeSocket();
    
    // Initialize Chess.js
    game = new Chess();
    
    // Setup event listeners
    setupEventListeners();
    
    // Initialize board after socket connects
    // Board will be initialized in handle_match_joined
});

// ==================== LOAD USER INFO ====================
async function loadUserInfo() {
    try {
        const response = await fetch('/api/auth/me', {
            credentials: 'include'
        });
        
        if (response.ok) {
            const data = await response.json();
            userId = data.user_id;
            document.getElementById('yourName').textContent = data.name;
            document.getElementById('yourElo').textContent = data.elo;
        } else {
            window.location.href = '/login';
        }
    } catch (error) {
        console.error('Failed to load user info:', error);
        showError('Failed to load user information');
    }
}

// ==================== WEBSOCKET SETUP ====================
function initializeSocket() {
    // Connect to Socket.IO server
    socket = io({
        transports: ['websocket', 'polling'],
        reconnection: true,
        reconnectionAttempts: MAX_RECONNECT_ATTEMPTS,
        reconnectionDelay: RECONNECT_DELAY
    });
    
    // ===== CONNECTION EVENTS =====
    socket.on('connect', () => {
        console.log('[+] Connected to server');
        updateConnectionStatus(true);
        reconnectAttempts = 0;
        
        // Join match room
        socket.emit('join_match', {
            match_id: matchId,
            user_id: userId
        });
    });
    
    socket.on('disconnect', (reason) => {
        console.log('[-] Disconnected:', reason);
        updateConnectionStatus(false);
        
        if (reason === 'io server disconnect') {
            // Server initiated disconnect, try to reconnect
            socket.connect();
        }
    });
    
    socket.on('connect_error', (error) => {
        console.error('Connection error:', error);
        updateConnectionStatus(false, 'Connection error');
    });
    
    socket.on('reconnect_attempt', (attemptNumber) => {
        console.log(`Reconnection attempt ${attemptNumber}...`);
        showConnectionBanner('Reconnecting...', 'warning');
    });
    
    socket.on('reconnect', (attemptNumber) => {
        console.log('[+] Reconnected after', attemptNumber, 'attempts');
        showConnectionBanner('Reconnected!', 'success');
        setTimeout(() => hideConnectionBanner(), 2000);
        
        // Rejoin match
        socket.emit('join_match', {
            match_id: matchId,
            user_id: userId
        });
    });
    
    socket.on('reconnect_failed', () => {
        console.error('[-] Reconnection failed');
        showConnectionBanner('Connection lost. Please refresh.', 'error');
    });
    
    // ===== MATCH EVENTS =====
    socket.on('match_joined', (data) => {
        console.log('[+] Match joined:', data);
        
        playerColor = data.your_color;
        opponentColor = playerColor === 'white' ? 'black' : 'white';
        
        // Update UI
        document.getElementById('yourColor').innerHTML = 
            `<span class="color-piece">${playerColor === 'white' ? '♔' : '♚'}</span> ${playerColor}`;
        document.getElementById('opponentColor').innerHTML = 
            `<span class="color-piece">${opponentColor === 'white' ? '♔' : '♚'}</span> ${opponentColor}`;
        
        // Update opponent info
        document.getElementById('opponentName').textContent = data.opponent.name;
        document.getElementById('opponentElo').textContent = data.opponent.elo;
        
        if (data.opponent.connected) {
            document.querySelector('#opponentStatus .status-dot').classList.add('online');
            document.querySelector('#opponentStatus .status-dot').classList.remove('offline');
        }
        
        // Initialize board with correct orientation
        initializeBoard();
        
        // Load existing moves if any
        if (data.pgn) {
            loadPGN(data.pgn);
        }
        
        // Check if it's my turn
        updateTurnIndicator();
    });
    
    socket.on('opponent_connected', (data) => {
        console.log('[+] Opponent connected');
        document.querySelector('#opponentStatus .status-dot').classList.add('online');
        document.querySelector('#opponentStatus .status-dot').classList.remove('offline');
        showNotification('Your opponent has joined!');
    });
    
    socket.on('opponent_disconnected', (data) => {
        console.log('[*] Opponent disconnected');
        document.querySelector('#opponentStatus .status-dot').classList.remove('online');
        document.querySelector('#opponentStatus .status-dot').classList.add('offline');
        showNotification('Your opponent disconnected', 'warning');
    });
    
    // ===== MOVE EVENTS =====
    socket.on('move_accepted', (data) => {
        console.log('[+] Move accepted:', data.move);
        isMyTurn = false;
        updateTurnIndicator();
    });
    
    socket.on('opponent_move', (data) => {
        console.log('♟️ Opponent moved:', data.move);
        
        // Make the move on the board
        const move = game.move(data.move);
        
        if (move) {
            board.position(game.fen());
            addMoveToHistory(move);
            updateCapturedPieces();
            updateTurnIndicator();
            
            // Check game state
            checkGameState();
            
            // Play sound (optional)
            playMoveSound();
            
            isMyTurn = true;
        }
    });
    
    socket.on('move_error', (data) => {
        console.error('[-] Move error:', data.message);
        showError(data.message);
    });
    
    // ===== GAME END EVENTS =====
    socket.on('game_ended', (data) => {
        console.log('🏁 Game ended:', data);
        gameActive = false;
        showGameEndModal(data);
    });
    
    socket.on('player_resigned', (data) => {
        console.log('🏳️ Player resigned:', data);
        gameActive = false;
        showGameEndModal({
            result: data.result,
            reason: 'resignation',
            white: data.white,
            black: data.black
        });
    });
    
    // ===== DRAW EVENTS =====
    socket.on('draw_offered', (data) => {
        console.log('[+] Draw offered');
        showDrawOfferModal();
    });
    
    socket.on('draw_accepted', (data) => {
        console.log('[+] Draw accepted');
        gameActive = false;
        showGameEndModal({
            result: 'draw',
            reason: 'agreement',
            white: data.white,
            black: data.black
        });
    });
    
    socket.on('draw_declined', (data) => {
        console.log('[-] Draw declined');
        showNotification('Draw offer declined', 'info');
    });
    
    // ===== CHAT EVENTS =====
    socket.on('chat_message', (data) => {
        addChatMessage(data);
    });
    
    // ===== UTILITY EVENTS =====
    socket.on('pong', (data) => {
        // Heartbeat response
    });
    
    socket.on('error', (data) => {
        console.error('[-] Socket error:', data.message);
        showError(data.message);
    });
}

// ==================== BOARD INITIALIZATION ====================
function initializeBoard() {
    const config = {
        position: 'start',
        orientation: playerColor,
        draggable: true,
        onDragStart: onDragStart,
        onDrop: onDrop,
        onSnapEnd: onSnapEnd,
        pieceTheme: 'https://chessboardjs.com/img/chesspieces/wikipedia/{piece}.png'
    };
    
    board = Chessboard('chessboard', config);
    
    // Fit board to container
    $(window).resize(() => board.resize());
}

// ==================== CHESS LOGIC ====================
function onDragStart(source, piece, position, orientation) {
    // Don't allow moves if game is over
    if (gameActive === false) return false;
    
    // Don't allow moves if not your turn
    if (!isMyTurn) {
        showNotification("It's not your turn!", 'warning');
        return false;
    }
    
    // Only pick up pieces for the player's color
    if ((playerColor === 'white' && piece.search(/^b/) !== -1) ||
        (playerColor === 'black' && piece.search(/^w/) !== -1)) {
        return false;
    }
    
    // Don't pick up pieces if in check and must move king
    // (chess.js handles this, but we can add UI feedback)
}

function onDrop(source, target) {
    // See if the move is legal
    const move = game.move({
        from: source,
        to: target,
        promotion: 'q' // Always promote to queen for simplicity
        // TODO: Add promotion choice dialog
    });
    
    // Illegal move
    if (move === null) {
        return 'snapback';
    }
    
    // Legal move - send to server
    socket.emit('make_move', {
        match_id: matchId,
        user_id: userId,
        move: move.san,  // Standard Algebraic Notation
        fen: game.fen()  // Board state
    });
    
    // Update UI
    addMoveToHistory(move);
    updateCapturedPieces();
    
    // Check game state
    checkGameState();
}

function onSnapEnd() {
    board.position(game.fen());
}

// ==================== GAME STATE CHECKING ====================
function checkGameState() {
    updateTurnIndicator();
    
    if (game.game_over()) {
        gameActive = false;
        
        let result, reason;
        
        if (game.in_checkmate()) {
            result = game.turn() === 'w' ? 'black_win' : 'white_win';
            reason = 'checkmate';
            showNotification('Checkmate!', 'error');
        } else if (game.in_draw()) {
            result = 'draw';
            if (game.in_stalemate()) {
                reason = 'stalemate';
            } else if (game.in_threefold_repetition()) {
                reason = 'repetition';
            } else if (game.insufficient_material()) {
                reason = 'insufficient material';
            } else {
                reason = '50-move rule';
            }
            showNotification(`Draw by ${reason}!`, 'info');
        }
        
        // Send game end to server
        socket.emit('game_end', {
            match_id: matchId,
            user_id: userId,
            result: result,
            reason: reason
        });
    } else if (game.in_check()) {
        const turn = game.turn() === 'w' ? 'White' : 'Black';
        showNotification(`${turn} is in check!`, 'warning');
        document.getElementById('gameStatus').textContent = 'Check!';
        document.getElementById('gameStatus').className = 'value status-check';
    }
}

// ==================== UI UPDATES ====================
function updateTurnIndicator() {
    const currentTurn = game.turn(); // 'w' or 'b'
    const turnColor = currentTurn === 'w' ? 'White' : 'Black';
    
    document.getElementById('turnIndicator').textContent = turnColor;
    
    const moveCount = Math.floor(game.history().length / 2) + 1;
    document.getElementById('moveNumber').textContent = moveCount;
    
    // Update move indicator
    const indicator = document.getElementById('moveIndicator');
    const indicatorText = indicator.querySelector('.indicator-text');
    
    if ((currentTurn === 'w' && playerColor === 'white') ||
        (currentTurn === 'b' && playerColor === 'black')) {
        isMyTurn = true;
        indicator.classList.add('your-turn');
        indicatorText.textContent = 'Your turn!';
    } else {
        isMyTurn = false;
        indicator.classList.remove('your-turn');
        indicatorText.textContent = 'Waiting for opponent...';
    }
}

function addMoveToHistory(move) {
    const history = document.getElementById('moveHistory');
    
    // Remove "no moves" message
    const noMoves = history.querySelector('.no-moves');
    if (noMoves) noMoves.remove();
    
    const moveNumber = Math.floor(game.history().length / 2);
    const isWhiteMove = move.color === 'w';
    
    // Create or get current row
    let currentRow = history.querySelector(`[data-move="${moveNumber}"]`);
    
    if (isWhiteMove) {
        currentRow = document.createElement('div');
        currentRow.className = 'move-row';
        currentRow.dataset.move = moveNumber;
        currentRow.innerHTML = `
            <div class="move-number">${moveNumber}.</div>
            <div class="move-white">${move.san}</div>
            <div class="move-black">-</div>
        `;
        history.appendChild(currentRow);
    } else {
        if (currentRow) {
            currentRow.querySelector('.move-black').textContent = move.san;
        }
    }
    
    // Scroll to bottom
    history.scrollTop = history.scrollHeight;
}

// ==================== CAPTURED PIECES ====================
function updateCapturedPieces() {
    const history = game.history({ verbose: true });
    const capturedByWhite = [];
    const capturedByBlack = [];
    
    history.forEach(move => {
        if (move.captured) {
            if (move.color === 'w') {
                capturedByWhite.push(move.captured);
            } else {
                capturedByBlack.push(move.captured);
            }
        }
    });
    
    // Update UI
    const pieceSymbols = {
        'p': '♟', 'n': '♞', 'b': '♝', 'r': '♜', 'q': '♛', 'k': '♚'
    };
    
    const yourCaptured = playerColor === 'white' ? capturedByWhite : capturedByBlack;
    const opponentCaptured = playerColor === 'white' ? capturedByBlack : capturedByWhite;
    
    document.getElementById('yourCaptured').innerHTML = yourCaptured
        .map(p => `<span class="captured-piece">${pieceSymbols[p]}</span>`)
        .join('');
    
    document.getElementById('opponentCaptured').innerHTML = opponentCaptured
        .map(p => `<span class="captured-piece">${pieceSymbols[p]}</span>`)
        .join('');
}

// ==================== LOAD PGN ====================
function loadPGN(pgn) {
    try {
        if (game.load_pgn(pgn)) {
            board.position(game.fen());
            
            // Rebuild move history
            const moves = game.history({ verbose: true });
            moves.forEach(move => addMoveToHistory(move));
            
            updateCapturedPieces();
            updateTurnIndicator();
        }
    } catch (error) {
        console.error('Failed to load PGN:', error);
    }
}

// ==================== EVENT LISTENERS ====================
function setupEventListeners() {
    // Resign button
    document.getElementById('resignBtn').addEventListener('click', () => {
        if (!gameActive) return;
        
        if (confirm('Are you sure you want to resign?')) {
            socket.emit('resign', {
                match_id: matchId,
                user_id: userId
            });
        }
    });
    
    // Offer draw button
    document.getElementById('offerDrawBtn').addEventListener('click', () => {
        if (!gameActive) return;
        
        socket.emit('offer_draw', {
            match_id: matchId,
            user_id: userId
        });
        
        showNotification('Draw offer sent', 'info');
    });
    
    // Flip board button
    document.getElementById('flipBoardBtn').addEventListener('click', () => {
        board.flip();
    });
    
    // Chat input
    const chatInput = document.getElementById('chatInput');
    const sendChatBtn = document.getElementById('sendChatBtn');
    
    sendChatBtn.addEventListener('click', sendChatMessage);
    chatInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            sendChatMessage();
        }
    });
    
    // Draw offer modal
    document.getElementById('acceptDrawBtn').addEventListener('click', () => {
        socket.emit('respond_draw', {
            match_id: matchId,
            user_id: userId,
            accepted: true
        });
        hideDrawOfferModal();
    });
    
    document.getElementById('declineDrawBtn').addEventListener('click', () => {
        socket.emit('respond_draw', {
            match_id: matchId,
            user_id: userId,
            accepted: false
        });
        hideDrawOfferModal();
    });
    
    // Heartbeat every 30 seconds
    setInterval(() => {
        if (socket && socket.connected) {
            socket.emit('ping');
        }
    }, 30000);
}

// ==================== CHAT FUNCTIONS ====================
function sendChatMessage() {
    const input = document.getElementById('chatInput');
    const message = input.value.trim();
    
    if (!message) return;
    
    socket.emit('chat_message', {
        match_id: matchId,
        user_id: userId,
        message: message
    });
    
    input.value = '';
}

function addChatMessage(data) {
    const chatMessages = document.getElementById('chatMessages');
    
    // Remove info message if exists
    const chatInfo = chatMessages.querySelector('.chat-info');
    if (chatInfo) chatInfo.remove();
    
    const isMine = data.sender_id === userId;
    const messageDiv = document.createElement('div');
    messageDiv.className = `chat-message ${isMine ? 'mine' : 'theirs'}`;
    
    const time = new Date(data.timestamp).toLocaleTimeString([], { 
        hour: '2-digit', 
        minute: '2-digit' 
    });
    
    messageDiv.innerHTML = `
        <div class="chat-sender">${isMine ? 'You' : data.sender_name}</div>
        <div class="chat-text">${escapeHtml(data.message)}</div>
        <div class="chat-time">${time}</div>
    `;
    
    chatMessages.appendChild(messageDiv);
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

// ==================== MODALS ====================
function showGameEndModal(data) {
    const modal = document.getElementById('gameEndModal');
    const icon = document.getElementById('resultIcon');
    const title = document.getElementById('resultTitle');
    const message = document.getElementById('resultMessage');
    const eloChanges = document.getElementById('eloChanges');
    
    let resultText, iconEmoji, messageText;
    
    if (data.result === 'draw') {
        resultText = "Draw";
        iconEmoji = "🤝";
        messageText = `Game ended in a draw by ${data.reason}`;
    } else {
        const winner = data.result === 'white_win' ? 'White' : 'Black';
        const didIWin = (data.result === 'white_win' && playerColor === 'white') ||
                       (data.result === 'black_win' && playerColor === 'black');
        
        resultText = didIWin ? "You Won!" : "You Lost";
        iconEmoji = didIWin ? "🏆" : "😔";
        messageText = `${winner} wins by ${data.reason}`;
    }
    
    icon.textContent = iconEmoji;
    title.textContent = resultText;
    message.textContent = messageText;
    
    // Show ELO changes if available
    if (data.white && data.black) {
        eloChanges.innerHTML = `
            <div class="elo-change-item">
                <div class="elo-change-label">White (${data.white.name})</div>
                <div class="elo-change-value">${data.white.elo}</div>
            </div>
            <div class="elo-change-item">
                <div class="elo-change-label">Black (${data.black.name})</div>
                <div class="elo-change-value">${data.black.elo}</div>
            </div>
        `;
    }
    
    modal.classList.remove('hidden');
}

function showDrawOfferModal() {
    document.getElementById('drawOfferModal').classList.remove('hidden');
}

function hideDrawOfferModal() {
    document.getElementById('drawOfferModal').classList.add('hidden');
}

// ==================== CONNECTION STATUS ====================
function updateConnectionStatus(connected, message) {
    const indicator = document.getElementById('connectionIndicator');
    const text = indicator.querySelector('.text');
    
    if (connected) {
        indicator.classList.add('connected');
        text.textContent = 'Connected';
    } else {
        indicator.classList.remove('connected');
        text.textContent = message || 'Disconnected';
    }
}

function showConnectionBanner(message, type = 'warning') {
    const banner = document.getElementById('connectionStatus');
    const text = banner.querySelector('.status-text');
    
    text.textContent = message;
    banner.className = `connection-banner ${type}`;
    banner.classList.remove('hidden');
}

function hideConnectionBanner() {
    document.getElementById('connectionStatus').classList.add('hidden');
}

// ==================== NOTIFICATIONS ====================
function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    
    notification.style.cssText = `
        position: fixed;
        top: 80px;
        right: 20px;
        background: ${type === 'error' ? '#ef4444' : type === 'warning' ? '#f59e0b' : '#10b981'};
        color: white;
        padding: 1rem 1.5rem;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.2);
        z-index: 9998;
        animation: slideInRight 0.3s ease-out;
        max-width: 300px;
    `;
    
    document.body.appendChild(notification);
    
    // Remove after 3 seconds
    setTimeout(() => {
        notification.style.animation = 'slideOutRight 0.3s ease-out';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

function showError(message) {
    showNotification(message, 'error');
}

// ==================== UTILITY FUNCTIONS ====================
function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}

function playMoveSound() {
    // Optional: Add move sound
    // const audio = new Audio('/static/sounds/move.mp3');
    // audio.play().catch(e => console.log('Audio play failed'));
}

// ==================== KEYBOARD SHORTCUTS ====================
document.addEventListener('keydown', (e) => {
    // ESC to close modals
    if (e.key === 'Escape') {
        document.querySelectorAll('.modal').forEach(modal => {
            modal.classList.add('hidden');
        });
    }
    
    // F to flip board
    if (e.key === 'f' || e.key === 'F') {
        board.flip();
    }
});

// ==================== PAGE VISIBILITY ====================
document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
        console.log('Page hidden');
    } else {
        console.log('Page visible');
        // Sync game state when user returns
        if (socket && socket.connected) {
            socket.emit('join_match', {
                match_id: matchId,
                user_id: userId
            });
        }
    }
});

// ==================== CLEANUP ====================
window.addEventListener('beforeunload', () => {
    if (socket) {
        socket.emit('leave_match', {
            match_id: matchId,
            user_id: userId
        });
        socket.disconnect();
    }
});

// ==================== ADD CSS ANIMATIONS ====================
const style = document.createElement('style');
style.textContent = `
    @keyframes slideInRight {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOutRight {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);

console.log('[+] Chess game initialized');