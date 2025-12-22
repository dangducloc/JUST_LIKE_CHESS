// ==================== BOT GAME STATE ====================
let socket = null;
let game = null;
let board = null;
let matchId = null;
let userId = null;
let playerColor = null;
let botDifficulty = null;
let isMyTurn = false;
let gameActive = true;

// ==================== INITIALIZATION ====================
document.addEventListener('DOMContentLoaded', async () => {
    const urlParams = new URLSearchParams(window.location.search);
    matchId = urlParams.get('match_id');
    botDifficulty = urlParams.get('difficulty') || 'medium';
    
    setTimeout(() => {
        document.getElementById('loadingOverlay').classList.add('hidden');
    }, 1000);
    
    await loadUserInfo();
    initializeSocket();
    game = new Chess();
    setupEventListeners();
    initPromotionHandlers();
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
    }
}

// ==================== WEBSOCKET SETUP ====================
function initializeSocket() {
    socket = io({
        transports: ['websocket', 'polling'],
        reconnection: true
    });
    
    socket.on('connect', () => {
        console.log('[+] Connected to server');
        updateConnectionStatus(true);
        
        if (matchId && matchId !== 'null' && matchId !== 'undefined') {
            // Join existing match
            console.log('[+] Joining existing match:', matchId);
            socket.emit('join_bot_match', {
                match_id: matchId,
                user_id: userId
            });
        } else {
            // Create new match
            console.log('[+] Creating new bot match, difficulty:', botDifficulty);
            socket.emit('create_bot_match', {
                user_id: userId,
                difficulty: botDifficulty
            });
        }
    });
    
    socket.on('disconnect', () => {
        console.log('[-] Disconnected');
        updateConnectionStatus(false);
    });
    
    socket.on('bot_match_created', (data) => {
        console.log('[+] Bot match created:', data);
        
        matchId = data.match_id;
        playerColor = data.your_color;
        botDifficulty = data.bot.difficulty;
        
        // Update URL without reloading
        const newUrl = `/game/bot?match_id=${matchId}&difficulty=${botDifficulty}`;
        window.history.pushState({}, '', newUrl);
        
        // Update UI
        updateBotMatchUI(data);
        
        // Initialize board AFTER getting match info
        initializeBoard();
        updateTurnIndicator();
        
        console.log('[+] Board initialized, player color:', playerColor);
    });
    
    socket.on('bot_match_joined', (data) => {
        console.log('[+] Bot match joined:', data);
        
        playerColor = data.your_color;
        botDifficulty = data.bot.difficulty;
        
        // Update UI
        updateBotMatchUI(data);
        
        // Initialize board
        initializeBoard();
        
        // Load existing moves if any
        if (data.pgn && data.pgn.trim() !== '') {
            loadPGN(data.pgn);
        }
        
        updateTurnIndicator();
    });
    
    socket.on('move_accepted', (data) => {
        console.log('[+] Move accepted:', data.move);
        isMyTurn = false;
        updateTurnIndicator();
        showNotification('Waiting for bot...', 'info');
    });
    
    socket.on('bot_move', (data) => {
        console.log('[+] Bot moved:', data.move);
        
        const move = game.move(data.move);
        
        if (move) {
            board.position(game.fen());
            addMoveToHistory(move);
            updateCapturedPieces();
            updateTurnIndicator();
            
            checkGameState();
            playMoveSound();
            
            isMyTurn = true;
            showNotification('Your turn!', 'success');
        } else {
            console.error('[-] Failed to apply bot move:', data.move);
        }
    });
    
    socket.on('move_error', (data) => {
        console.error('[-] Move error:', data.message);
        showError(data.message);
    });
    
    socket.on('bot_game_ended', (data) => {
        console.log('[+] Bot game ended:', data);
        gameActive = false;
        showBotGameEndModal(data);
    });
    
    socket.on('error', (data) => {
        console.error('[-] Socket error:', data.message);
        showError(data.message);
    });
}

// ==================== UPDATE UI ====================
function updateBotMatchUI(data) {
    document.getElementById('yourColor').innerHTML = 
        `<span class="color-piece">${playerColor === 'white' ? '♔' : '♚'}</span> ${playerColor}`;
    
    document.getElementById('opponentName').textContent = data.bot.name;
    document.getElementById('opponentElo').textContent = data.bot.elo;
    document.getElementById('opponentColor').innerHTML = 
        `<span class="color-piece">${playerColor === 'white' ? '♚' : '♔'}</span> ${playerColor === 'white' ? 'black' : 'white'}`;
    
    document.querySelector('#opponentStatus .status-dot').classList.add('online');
    document.getElementById('matchIdDisplay').textContent = matchId;
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
    $(window).resize(() => board.resize());
}

// ==================== CHESS LOGIC ====================
function onDragStart(source, piece, position, orientation) {
    if (!gameActive) {
        showNotification("Game is over", 'warning');
        return false;
    }
    
    if (!isMyTurn) {
        showNotification("Wait for bot's move!", 'warning');
        return false;
    }
    
    if ((playerColor === 'white' && piece.search(/^b/) !== -1) ||
        (playerColor === 'black' && piece.search(/^w/) !== -1)) {
        return false;
    }
    
    return true;
}

function onDrop(source, target) {
    if (isPromotionMove(source, target)) {
        showPromotionModal(source, target, (promotionPiece) => {
            executeMoveWithPromotion(source, target, promotionPiece);
        });
        return 'snapback';
    }
    
    return executeMove(source, target);
}

function executeMove(source, target, promotion = null) {
    const moveConfig = { from: source, to: target };
    if (promotion) moveConfig.promotion = promotion;
    
    const move = game.move(moveConfig);
    
    if (!move) {
        return 'snapback';
    }
    
    socket.emit('bot_player_move', {
        match_id: matchId,
        user_id: userId,
        move: move.san,
        fen: game.fen()
    });
    
    addMoveToHistory(move);
    updateCapturedPieces();
    checkGameState();
    
    return null;
}

function executeMoveWithPromotion(source, target, promotionPiece) {
    const move = game.move({
        from: source,
        to: target,
        promotion: promotionPiece
    });
    
    if (move) {
        board.position(game.fen());
        
        socket.emit('bot_player_move', {
            match_id: matchId,
            user_id: userId,
            move: move.san,
            fen: game.fen()
        });
        
        addMoveToHistory(move);
        updateCapturedPieces();
        checkGameState();
        playPromotionSound();
    }
}

function onSnapEnd() {
    board.position(game.fen());
}

// ==================== GAME STATE ====================
function checkGameState() {
    updateTurnIndicator();
    
    if (game.game_over()) {
        gameActive = false;
    } else if (game.in_check()) {
        const turn = game.turn() === 'w' ? 'White' : 'Black';
        showNotification(`${turn} is in check!`, 'warning');
    }
}

function updateTurnIndicator() {
    const currentTurn = game.turn();
    const turnColor = currentTurn === 'w' ? 'White' : 'Black';
    
    document.getElementById('turnIndicator').textContent = turnColor;
    const moveCount = Math.floor(game.history().length / 2) + 1;
    document.getElementById('moveNumber').textContent = moveCount;
    
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
        indicatorText.textContent = 'Bot is thinking...';
    }
}

function addMoveToHistory(move) {
    const history = document.getElementById('moveHistory');
    const noMoves = history.querySelector('.no-moves');
    if (noMoves) noMoves.remove();
    
    const moveNumber = Math.ceil(game.history().length / 2);
    const isWhiteMove = move.color === 'w';
    
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
    
    history.scrollTop = history.scrollHeight;
}

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

function loadPGN(pgn) {
    try {
        if (game.load_pgn(pgn)) {
            board.position(game.fen());
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
    document.getElementById('resignBtn').addEventListener('click', () => {
        if (!gameActive) return;
        if (confirm('Are you sure you want to resign?')) {
            socket.emit('bot_resign', {
                match_id: matchId,
                user_id: userId
            });
        }
    });
    
    document.getElementById('flipBoardBtn').addEventListener('click', () => {
        board.flip();
        showNotification('Board flipped', 'info');
    });
}

// ==================== GAME END MODAL ====================
function showBotGameEndModal(data) {
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
    } else if (data.result === 'player_win') {
        resultText = "You Won!";
        iconEmoji = "🏆";
        messageText = `You defeated the bot by ${data.reason}`;
    } else {
        resultText = "You Lost";
        iconEmoji = "😔";
        messageText = `Bot won by ${data.reason}`;
    }
    
    icon.textContent = iconEmoji;
    title.textContent = resultText;
    message.textContent = messageText;
    
    if (data.player_elo) {
        eloChanges.innerHTML = `
            <div class="elo-change-item">
                <div class="elo-change-label">Your New ELO</div>
                <div class="elo-change-value">${data.player_elo}</div>
            </div>
        `;
    }
    
    modal.classList.remove('hidden');
}

// ==================== UTILITIES ====================
function updateConnectionStatus(connected) {
    const indicator = document.getElementById('connectionIndicator');
    const text = indicator.querySelector('.text');
    
    if (connected) {
        indicator.classList.add('connected');
        text.textContent = 'Connected';
    } else {
        indicator.classList.remove('connected');
        text.textContent = 'Disconnected';
    }
}

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
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
    `;
    document.body.appendChild(notification);
    setTimeout(() => {
        notification.style.animation = 'slideOutRight 0.3s ease-out';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

function showError(message) {
    showNotification(message, 'error');
}

function playMoveSound() {
    try {
        const audio = new Audio('/static/sounds/move.mp3');
        audio.volume = 0.5;
        audio.play().catch(() => {});
    } catch (e) {}
}

function playPromotionSound() {
    try {
        const audio = new Audio('/static/sounds/promote.mp3');
        audio.volume = 0.5;
        audio.play().catch(() => {});
    } catch (e) {}
}

window.addEventListener('beforeunload', () => {
    if (socket) {
        socket.emit('leave_bot_match', {
            match_id: matchId,
            user_id: userId
        });
        socket.disconnect();
    }
});

console.log('[+] Bot game initialized');