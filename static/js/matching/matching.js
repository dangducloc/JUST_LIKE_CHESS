// Matching Page JavaScript - Enhanced with auto-redirect
let currentState = 'idle';
let pollingInterval = null;
let waitStartTime = null;
let currentMatchId = null;
let autoRedirectTimeout = null;

// Configuration
const AUTO_REDIRECT_DELAY = 3000; // 3 seconds delay before auto-redirect
const POLLING_INTERVAL = 2000; // Poll every 2 seconds

// DOM Elements
const idleState = document.getElementById('idleState');
const waitingState = document.getElementById('waitingState');
const matchedState = document.getElementById('matchedState');

const findMatchBtn = document.getElementById('findMatchBtn');
const cancelMatchBtn = document.getElementById('cancelMatchBtn');
const startGameBtn = document.getElementById('startGameBtn');

// Initialize
document.addEventListener('DOMContentLoaded', async () => {
    await loadUserInfo();
    await loadStats();
    await loadMatchHistory();
    await loadLeaderboard();
    
    // Check if already in a match
    await checkCurrentMatch();
    
    setupEventListeners();
});

// Event Listeners
function setupEventListeners() {
    findMatchBtn.addEventListener('click', findMatch);
    cancelMatchBtn.addEventListener('click', cancelMatch);
    startGameBtn.addEventListener('click', () => startGame(false)); // Manual start
}

// Load User Info
async function loadUserInfo() {
    try {
        const response = await fetch('/api/auth/me', {
            credentials: 'include'
        });
        
        if (response.ok) {
            const data = await response.json();
            document.getElementById('userName').textContent = data.name;
            document.getElementById('userElo').textContent = `ELO: ${data.elo}`;
        } else {
            window.location.href = '/login';
        }
    } catch (error) {
        console.error('Failed to load user info:', error);
    }
}

// Load Stats
async function loadStats() {
    try {
        const response = await fetch('/api/match/stats', {
            credentials: 'include'
        });
        
        if (response.ok) {
            const stats = await response.json();
            document.getElementById('totalGames').textContent = stats.total_games;
            document.getElementById('wins').textContent = stats.wins;
            document.getElementById('losses').textContent = stats.losses;
            document.getElementById('winRate').textContent = `${stats.win_rate}%`;
        }
    } catch (error) {
        console.error('Failed to load stats:', error);
    }
}

// Load Match History
async function loadMatchHistory() {
    try {
        const response = await fetch('/api/match/history?limit=5', {
            credentials: 'include'
        });
        
        if (response.ok) {
            const data = await response.json();
            displayMatchHistory(data.matches);
        }
    } catch (error) {
        console.error('Failed to load match history:', error);
    }
}

function displayMatchHistory(matches) {
    const container = document.getElementById('matchHistory');
    
    if (matches.length === 0) {
        container.innerHTML = '<p class="loading">No matches yet</p>';
        return;
    }
    
    container.innerHTML = matches.map(match => {
        const resultClass = getResultClass(match.result, match.your_color);
        const resultText = getResultText(match.result, match.your_color);
        
        return `
            <div class="match-item">
                <div>
                    <div class="match-opponent">
                    ${match.opponent_name} <span style="font-size: 0.85rem; color: #6b7280;">(${match.opponent_elo}) </span><br>
                    Started at: <span style="font-size: 0.85rem; color: #6b7280;">${new Date(match.start).toLocaleDateString()}</span>
                    &nbsp; &nbsp; &nbsp;&nbsp;&nbsp;
                    Ended at: <span style="font-size: 0.85rem; color: #6b7280;">${new Date(match.end).toLocaleDateString()}</span>
                    </div>
                    <div style="font-size: 0.85rem; color: #6b7280;">
                        You played as ${match.your_color}
                    </div>
                </div>
                <span class="match-result ${resultClass}">${resultText}</span>
            </div>
        `;
    }).join('');
}

function getResultClass(result, yourColor) {
    if (result === 'draw') return 'draw';
    if ((result === 'white_win' && yourColor === 'white') ||
        (result === 'black_win' && yourColor === 'black')) {
        return 'win';
    }
    return 'loss';
}

function getResultText(result, yourColor) {
    if (result === 'draw') return 'Draw';
    if ((result === 'white_win' && yourColor === 'white') ||
        (result === 'black_win' && yourColor === 'black')) {
        return 'Win';
    }
    return 'Loss';
}

// Load Leaderboard
async function loadLeaderboard() {
    try {
        const response = await fetch('/api/match/leaderboard?limit=10');
        
        if (response.ok) {
            const data = await response.json();
            displayLeaderboard(data.leaderboard);
        }
    } catch (error) {
        console.error('Failed to load leaderboard:', error);
    }
}

function displayLeaderboard(players) {
    const container = document.getElementById('leaderboardList');
    
    if (players.length === 0) {
        container.innerHTML = '<p class="loading">No players yet</p>';
        return;
    }
    
    container.innerHTML = players.map(player => {
        let rankClass = '';
        if (player.rank === 1) rankClass = 'top1';
        else if (player.rank === 2) rankClass = 'top2';
        else if (player.rank === 3) rankClass = 'top3';
        
        return `
            <div class="leaderboard-item">
                <div class="rank ${rankClass}">#${player.rank}</div>
                <div class="player-info">
                    <div class="player-name">${player.name}</div>
                    <div class="player-stats">
                        ELO: ${player.elo} | Games: ${player.games_played} | Win Rate: ${player.win_rate}%
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

// Find Match
async function findMatch() {
    try {
        findMatchBtn.disabled = true;
        findMatchBtn.textContent = 'Searching...';
        
        const response = await fetch('/api/matching/find_match', {
            method: 'POST',
            credentials: 'include'
        });
        
        const data = await response.json();
        
        if (data.status === 'matched') {
            // Immediately found a match
            showMatchedState(data, true); // Pass autoRedirect = true
        } else if (data.status === 'waiting') {
            // Added to queue
            showWaitingState(data);
            startPolling();
        } else {
            alert(data.message || 'Failed to find match');
            findMatchBtn.disabled = false;
            findMatchBtn.textContent = '🎯 Find Match';
        }
    } catch (error) {
        console.error('Find match error:', error);
        alert('Network error. Please try again.');
        findMatchBtn.disabled = false;
        findMatchBtn.textContent = '🎯 Find Match';
    }
}

// Cancel Match
async function cancelMatch() {
    try {
        const response = await fetch('/api/matching/cancel_match', {
            method: 'POST',
            credentials: 'include'
        });
        
        if (response.ok) {
            stopPolling();
            clearAutoRedirect();
            showIdleState();
        }
    } catch (error) {
        console.error('Cancel match error:', error);
    }
}

// Start Polling
function startPolling() {
    waitStartTime = Date.now();
    updateWaitTime();
    
    pollingInterval = setInterval(async () => {
        await checkMatch();
        updateWaitTime();
    }, POLLING_INTERVAL);
}

function stopPolling() {
    if (pollingInterval) {
        clearInterval(pollingInterval);
        pollingInterval = null;
    }
}

function updateWaitTime() {
    if (waitStartTime) {
        const seconds = Math.floor((Date.now() - waitStartTime) / 1000);
        document.getElementById('waitTime').textContent = `${seconds}s`;
    }
}

// Check Match Status (called by polling)
async function checkMatch() {
    try {
        const response = await fetch('/api/matching/check_match', {
            credentials: 'include'
        });
        
        if (response.ok) {
            const data = await response.json();
            
            if (data.status === 'matched') {
                stopPolling();
                showMatchedState(data, true); // Auto-redirect enabled
            }
        }
    } catch (error) {
        console.error('Check match error:', error);
    }
}

// Check Current Match (on page load)
async function checkCurrentMatch() {
    try {
        const response = await fetch('/api/matching/check_match', {
            credentials: 'include'
        });
        
        if (response.ok) {
            const data = await response.json();
            
            if (data.status === 'matched') {
                // Found existing match on page load
                showMatchedState(data, true); // Auto-redirect enabled
            } else if (data.status === 'waiting') {
                showWaitingState(data);
                startPolling();
            }
        }
    } catch (error) {
        console.error('Check current match error:', error);
    }
}

// State Management
function showIdleState() {
    currentState = 'idle';
    idleState.style.display = 'block';
    waitingState.style.display = 'none';
    matchedState.style.display = 'none';
    
    findMatchBtn.disabled = false;
    findMatchBtn.textContent = '🎯 Find Match';
}

function showWaitingState(data) {
    currentState = 'waiting';
    idleState.style.display = 'none';
    waitingState.style.display = 'block';
    matchedState.style.display = 'none';
    
    if (data.elo) {
        const min = data.elo - 100;
        const max = data.elo + 100;
        document.getElementById('eloRange').textContent = `${min} - ${max}`;
    }
    
    if (data.queue_position) {
        document.getElementById('queuePosition').textContent = data.queue_position;
    }
}

function showMatchedState(data, autoRedirect = false) {
    currentState = 'matched';
    idleState.style.display = 'none';
    waitingState.style.display = 'none';
    matchedState.style.display = 'block';
    
    currentMatchId = data.match_id;
    
    document.getElementById('opponentName').textContent = data.opponent.name;
    document.getElementById('opponentElo').textContent = data.opponent.elo;
    
    const colorBadge = document.getElementById('yourColor');
    colorBadge.textContent = data.your_color;
    colorBadge.className = `color-badge ${data.your_color}`;
    
    // Auto-redirect if enabled
    if (autoRedirect) {
        startAutoRedirectCountdown();
    }
}

// Auto-redirect functionality
function startAutoRedirectCountdown() {
    let countdown = Math.floor(AUTO_REDIRECT_DELAY / 1000);
    
    // Update button text with countdown
    updateStartButtonCountdown(countdown);
    
    // Create countdown interval
    const countdownInterval = setInterval(() => {
        countdown--;
        if (countdown > 0) {
            updateStartButtonCountdown(countdown);
        } else {
            clearInterval(countdownInterval);
        }
    }, 1000);
    
    // Set timeout for actual redirect
    autoRedirectTimeout = setTimeout(() => {
        clearInterval(countdownInterval);
        startGame(true); // Auto start
    }, AUTO_REDIRECT_DELAY);
}

function updateStartButtonCountdown(seconds) {
    if (startGameBtn) {
        startGameBtn.textContent = `Starting in ${seconds}s... (Click to start now)`;
        startGameBtn.classList.add('countdown');
    }
}

function clearAutoRedirect() {
    if (autoRedirectTimeout) {
        clearTimeout(autoRedirectTimeout);
        autoRedirectTimeout = null;
    }
    
    // Reset button text
    if (startGameBtn) {
        startGameBtn.textContent = 'Start Game';
        startGameBtn.classList.remove('countdown');
    }
}

// Start Game
function startGame(isAutoStart = false) {
    if (currentMatchId) {
        // Clear auto-redirect if user clicked manually
        if (!isAutoStart) {
            clearAutoRedirect();
        }
        
        console.log(`${isAutoStart ? 'Auto-' : 'Manual '}starting game:`, currentMatchId);
        
        // Redirect to game page
        window.location.href = `/game/${currentMatchId}`;
    } else {
        console.error('No match ID available');
        alert('Error: No match found. Please try again.');
    }
}

// Logout
async function logout() {
    // Clear any pending redirects
    clearAutoRedirect();
    stopPolling();
    
    try {
        const response = await fetch('/api/auth/logout', {
            method: 'POST',
            credentials: 'include'
        });
        
        if (response.ok) {
            window.location.href = '/login';
        }
    } catch (error) {
        console.error('Logout error:', error);
    }
}

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    stopPolling();
    clearAutoRedirect();
});

// Add visual feedback styles dynamically
const style = document.createElement('style');
style.textContent = `
    .btn.countdown {
        animation: pulse 1s infinite;
        background: linear-gradient(135deg, #10b981, #059669) !important;
    }
    
    @keyframes pulse {
        0%, 100% {
            transform: scale(1);
            box-shadow: 0 6px 20px rgba(16, 185, 129, 0.4);
        }
        50% {
            transform: scale(1.05);
            box-shadow: 0 8px 25px rgba(16, 185, 129, 0.6);
        }
    }
    
    .matched-card .countdown-notice {
        margin-top: 1rem;
        padding: 0.75rem;
        background: #d1fae5;
        border: 2px solid #10b981;
        border-radius: 8px;
        color: #065f46;
        font-weight: 600;
        animation: fadeIn 0.3s ease-out;
    }
    
    @keyframes fadeIn {
        from {
            opacity: 0;
            transform: translateY(-10px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
`;
document.head.appendChild(style);