// ==================== GAME STATE ====================
let analysis = null;
let game = null;
let board = null;
let currentPly = 0;
let autoPlayInterval = null;
let evalChart = null;

// ==================== INITIALIZATION ====================
document.addEventListener('DOMContentLoaded', async () => {
    const matchId = document.getElementById('matchId').value;
    
    // Load analysis data
    await loadAnalysis(matchId);
    
    // Setup event listeners
    setupEventListeners();
});

// ==================== LOAD ANALYSIS ====================
async function loadAnalysis(matchId) {
    try {
        const response = await fetch(`/api/review/${matchId}`, {
            credentials: 'include'
        });
        
        if (!response.ok) {
            throw new Error('Failed to load analysis');
        }
        
        analysis = await response.json();
        
        // Hide loading
        document.getElementById('loadingOverlay').classList.add('hidden');
        
        // Initialize display
        initializeBoard();
        displayGameInfo();
        displayMoveList();
        displayStats();
        createEvalChart();
        findKeyMoments();
        
    } catch (error) {
        console.error('Error loading analysis:', error);
        showError('Failed to load game analysis. Please try again.');
    }
}

// ==================== INITIALIZE BOARD ====================
function initializeBoard() {
    game = new Chess();
    
    const config = {
        position: 'start',
        draggable: false,
        pieceTheme: 'https://chessboardjs.com/img/chesspieces/wikipedia/{piece}.png'
    };
    
    board = Chessboard('reviewBoard', config);
    
    // Fit board to container
    $(window).resize(() => board.resize());
}

// ==================== DISPLAY GAME INFO ====================
function displayGameInfo() {
    // Update player names
    document.getElementById('whiteName').textContent = analysis.white.username;
    document.getElementById('blackName').textContent = analysis.black.username;
    
    // Calculate and display stats
    const whiteStats = calculatePlayerStats('white');
    const blackStats = calculatePlayerStats('black');
    
    // White stats
    document.getElementById('whiteBlunders').textContent = whiteStats.blunders;
    document.getElementById('whiteMistakes').textContent = whiteStats.mistakes;
    document.getElementById('whiteElo').textContent = analysis.white.elo;
    document.getElementById('whiteInaccuracies').textContent = whiteStats.inaccuracies;
    document.getElementById('whiteAvgLoss').textContent = whiteStats.avgLoss.toFixed(2);
    
    // Black stats
    document.getElementById('blackBlunders').textContent = blackStats.blunders;
    document.getElementById('blackMistakes').textContent = blackStats.mistakes;
    document.getElementById('blackElo').textContent = analysis.black.elo;
    document.getElementById('blackInaccuracies').textContent = blackStats.inaccuracies;
    document.getElementById('blackAvgLoss').textContent = blackStats.avgLoss.toFixed(2);
    
    // Game result
    const resultMap = {
        'white_win': '1-0',
        'black_win': '0-1',
        'draw': '½-½',
        'ongoing': '?'
    };
    document.getElementById('gameResult').textContent = resultMap[analysis.status] || '?';
}

// ==================== CALCULATE PLAYER STATS ====================
function calculatePlayerStats(color) {
    const moves = analysis.analysis.filter(m => m.color === color);
    
    const stats = {
        blunders: 0,
        mistakes: 0,
        inaccuracies: 0,
        avgLoss: 0
    };
    
    moves.forEach(move => {
        if (move.judgment === 'BLUNDER') stats.blunders++;
        if (move.judgment === 'MISTAKE') stats.mistakes++;
        if (move.judgment === 'INACCURACY') stats.inaccuracies++;
        stats.avgLoss += move.loss;
    });
    
    stats.avgLoss = moves.length > 0 ? stats.avgLoss / moves.length : 0;
    
    return stats;
}

// ==================== DISPLAY STATS ====================
function displayStats() {
    const totalMoves = analysis.move_count;
    const accurateMoves = analysis.analysis.filter(m => m.judgment === 'OK').length;
    const totalErrors = analysis.analysis.filter(m => m.judgment !== 'OK').length;
    const criticalMoments = analysis.analysis.filter(m => 
        m.judgment === 'BLUNDER' || m.loss_cp > 200
    ).length;
    
    document.getElementById('totalMoves').textContent = totalMoves;
    document.getElementById('accurateMoves').textContent = accurateMoves;
    document.getElementById('totalErrors').textContent = totalErrors;
    document.getElementById('criticalMoments').textContent = criticalMoments;
}

// ==================== DISPLAY MOVE LIST ====================
function displayMoveList() {
    const container = document.getElementById('moveList');
    container.innerHTML = '';
    
    analysis.analysis.forEach((move, index) => {
        const moveItem = createMoveItem(move, index);
        container.appendChild(moveItem);
    });
}

function createMoveItem(move, index) {
    const div = document.createElement('div');
    div.className = `move-item ${index === currentPly ? 'active' : ''}`;
    div.dataset.ply = index;
    
    const judgmentClass = move.judgment.toLowerCase().replace('_', '-');
    
    div.innerHTML = `
        <div class="move-item-header">
            <span class="move-number">${move.ply}.</span>
            <span class="move-eval">${move.eval_after}</span>
        </div>
        <div class="move-item-body">
            <span class="move-san">${move.move}</span>
            <span class="move-judgment ${judgmentClass}">${move.judgment}</span>
        </div>
    `;
    
    div.addEventListener('click', () => goToPly(index));
    
    return div;
}

// ==================== NAVIGATION ====================
function goToPly(ply) {
    if (ply < 0 || ply >= analysis.analysis.length) return;
    
    currentPly = ply;
    
    // Reset game and replay moves up to current ply
    game.reset();
    for (let i = 0; i <= ply; i++) {
        game.move(analysis.analysis[i].move);
    }
    
    // Update board
    board.position(game.fen());
    
    // Update UI
    updateCurrentMoveDisplay();
    updateMoveListActive();
}

function updateCurrentMoveDisplay() {
    const move = analysis.analysis[currentPly];
    
    document.getElementById('currentMoveNumber').textContent = move.ply;
    document.getElementById('currentMove').textContent = move.move;
    document.getElementById('evalBefore').textContent = move.eval_before;
    document.getElementById('evalAfter').textContent = move.eval_after;
    
    // Update judgment badge
    const badge = document.getElementById('moveBadge');
    badge.textContent = move.judgment;
    badge.className = `judgment-badge ${move.judgment.toLowerCase()}`;
    
    // Show/hide best move container
    const bestMoveContainer = document.getElementById('bestMoveContainer');
    if (move.judgment !== 'OK') {
        bestMoveContainer.style.display = 'block';
        document.getElementById('bestMove').textContent = move.best_move;
        document.getElementById('moveLoss').textContent = move.loss.toFixed(2);
    } else {
        bestMoveContainer.style.display = 'none';
    }
}

function updateMoveListActive() {
    document.querySelectorAll('.move-item').forEach(item => {
        item.classList.toggle('active', parseInt(item.dataset.ply) === currentPly);
    });
}

// ==================== EVENT LISTENERS ====================
function setupEventListeners() {
    // Navigation buttons
    document.getElementById('startBtn').addEventListener('click', () => goToPly(0));
    document.getElementById('prevBtn').addEventListener('click', () => goToPly(currentPly - 1));
    document.getElementById('nextBtn').addEventListener('click', () => goToPly(currentPly + 1));
    document.getElementById('endBtn').addEventListener('click', () => goToPly(analysis.analysis.length - 1));
    
    // Auto-play button
    document.getElementById('playBtn').addEventListener('click', toggleAutoPlay);
    
    // Flip board
    document.getElementById('flipBtn').addEventListener('click', () => {
        board.flip();
    });
    
    // Filter buttons
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', () => filterMoves(btn.dataset.filter));
    });
    
    // Export button
    document.getElementById('exportBtn').addEventListener('click', exportAnalysis);
    
    // Share button
    document.getElementById('shareBtn').addEventListener('click', showShareModal);
    
    // Keyboard shortcuts
    document.addEventListener('keydown', handleKeyPress);
}

function handleKeyPress(e) {
    switch(e.key) {
        case 'ArrowLeft':
            goToPly(currentPly - 1);
            break;
        case 'ArrowRight':
            goToPly(currentPly + 1);
            break;
        case 'Home':
            goToPly(0);
            break;
        case 'End':
            goToPly(analysis.analysis.length - 1);
            break;
        case ' ':
            e.preventDefault();
            toggleAutoPlay();
            break;
        case 'f':
            board.flip();
            break;
    }
}

// ==================== AUTO-PLAY ====================
function toggleAutoPlay() {
    const btn = document.getElementById('playBtn');
    
    if (autoPlayInterval) {
        clearInterval(autoPlayInterval);
        autoPlayInterval = null;
        btn.textContent = '▶️';
    } else {
        btn.textContent = '⏸️';
        autoPlayInterval = setInterval(() => {
            if (currentPly < analysis.analysis.length - 1) {
                goToPly(currentPly + 1);
            } else {
                toggleAutoPlay(); // Stop at end
            }
        }, 1000);
    }
}

// ==================== FILTER MOVES ====================
function filterMoves(filter) {
    // Update active button
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.filter === filter);
    });
    
    // Filter move items
    document.querySelectorAll('.move-item').forEach(item => {
        const ply = parseInt(item.dataset.ply);
        const move = analysis.analysis[ply];
        
        let show = true;
        if (filter === 'blunders') {
            show = move.judgment === 'BLUNDER';
        } else if (filter === 'mistakes') {
            show = move.judgment === 'MISTAKE';
        } else if (filter === 'inaccuracies') {
            show = move.judgment === 'INACCURACY';
        }
        
        item.style.display = show ? 'block' : 'none';
    });
}

// ==================== EVALUATION CHART ====================
const evalBackgroundPlugin = {
    id: 'evalBackground',
    beforeDraw(chart) {
        const { ctx, chartArea } = chart;
        if (!chartArea) return;

        const dataset = chart.data.datasets[0];
        const values = dataset.data;

        let index = chart._active?.[0]?.index;
        if (index == null) index = values.length - 1;

        const y = values[index];
        if (isNaN(y)) return;

        ctx.save();
        ctx.fillStyle =
            y > 0
                ? 'rgba(34,197,94,0.08)'   // green background
                : y < 0
                ? 'rgba(239,68,68,0.08)'   // red background
                : 'rgba(0,0,0,0)';

        ctx.fillRect(
            chartArea.left,
            chartArea.top,
            chartArea.right - chartArea.left,
            chartArea.bottom - chartArea.top
        );
        ctx.restore();
    }
};

function createEvalChart() {
    const canvas = document.getElementById('evalChart');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');

    if (evalChart) evalChart.destroy();

    const values = analysis.analysis.map(m => parseEval(m.eval_after));
    const labels = values.map((_, i) => i + 1);

    evalChart = new Chart(ctx, {
        type: 'line',
        plugins: [evalBackgroundPlugin],
        data: {
            labels,
            datasets: [{
                data: values,
                borderWidth: 2,
                pointRadius: 0,
                tension: 0.15,
                spanGaps: true,

                /* LINE COLOR */
                segment: {
                    borderColor: ctx => {
                        const y0 = ctx.p0.parsed.y;
                        const y1 = ctx.p1.parsed.y;
                        if (y0 >= 0 && y1 >= 0) return '#22c55e';
                        if (y0 <= 0 && y1 <= 0) return '#ef4444';
                        return '#f59e0b';
                    }
                },

                /* FILL */
                fill: { target: 'origin' },
                backgroundColor: ctx => {
                    const y = ctx.raw;
                    if (y > 0) return 'rgba(34,197,94,0.25)';
                    if (y < 0) return 'rgba(239,68,68,0.25)';
                    return 'rgba(0,0,0,0)';
                }
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                intersect: false,
                mode: 'index'
            },
            scales: {
                x: {
                    title: {
                        display: true,
                        text: 'Move Number'
                    }
                },
                y: {
                    min: -10,
                    max: 10,
                    title: {
                        display: true,
                        text: 'Evaluation (pawns)'
                    },
                    grid: {
                        color: ctx =>
                            ctx.tick.value === 0
                                ? '#94a3b8'
                                : 'rgba(0,0,0,0.05)',
                        lineWidth: ctx =>
                            ctx.tick.value === 0 ? 2 : 1
                    }
                }
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: ctx => `Eval: ${ctx.parsed.y.toFixed(2)}`
                    }
                }
            }
        }
    });
}

function parseEval(evalStr) {
    if (!evalStr) return NaN;

    if (evalStr.includes('M')) {
        const m = parseInt(evalStr.replace(/[^\d-]/g, ''));
        return m > 0 ? 10 : -10;
    }

    const v = parseFloat(evalStr);
    return isNaN(v) ? NaN : v;
}


// ==================== KEY MOMENTS ====================
function findKeyMoments() {
    const keyMoments = analysis.analysis.filter(move => 
        move.judgment === 'BLUNDER' || move.loss_cp > 150
    );
    
    const container = document.getElementById('keyMoments');
    
    if (keyMoments.length === 0) {
        container.innerHTML = '<p style="color: #6b7280; text-align: center;">No critical mistakes found</p>';
        return;
    }
    
    container.innerHTML = '';
    
    keyMoments.forEach(move => {
        const item = document.createElement('div');
        item.className = 'key-moment-item';
        item.innerHTML = `
            <div class="key-moment-header">
                <span class="key-moment-move">Move ${move.ply}: ${move.move}</span>
                <span class="key-moment-type">${move.judgment}</span>
            </div>
            <div class="key-moment-description">
                Better: ${move.best_move} (Loss: ${move.loss.toFixed(2)} pawns)
            </div>
        `;
        
        item.addEventListener('click', () => {
            const ply = analysis.analysis.findIndex(m => m.ply === move.ply);
            goToPly(ply);
        });
        
        container.appendChild(item);
    });
}

// ==================== EXPORT ANALYSIS ====================
function exportAnalysis() {
    const report = {
        match_id: analysis.match_id,
        white: analysis.white,
        black: analysis.black,
        result: analysis.status,
        date: new Date().toISOString(),
        summary: {
            white: calculatePlayerStats('white'),
            black: calculatePlayerStats('black')
        },
        moves: analysis.analysis,
        pgn: analysis.pgn
    };
    
    const blob = new Blob([JSON.stringify(report, null, 2)], { 
        type: 'application/json' 
    });
    
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `analysis_${analysis.match_id}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    showNotification('Analysis exported successfully!');
}

// ==================== SHARE MODAL ====================
function showShareModal() {
    const modal = document.getElementById('shareModal');
    const shareLink = `${window.location.origin}/review/${analysis.match_id}`;
    document.getElementById('shareLink').value = shareLink;
    modal.classList.remove('hidden');
}

function closeShareModal() {
    document.getElementById('shareModal').classList.add('hidden');
}

function copyShareLink() {
    const input = document.getElementById('shareLink');
    input.select();
    document.execCommand('copy');
    showNotification('Link copied to clipboard!');
}

// ==================== ERROR HANDLING ====================
function showError(message) {
    document.getElementById('loadingOverlay').classList.add('hidden');
    document.getElementById('errorMessage').textContent = message;
    document.getElementById('errorModal').classList.remove('hidden');
}

// ==================== NOTIFICATIONS ====================
function showNotification(message) {
    const notification = document.createElement('div');
    notification.className = 'notification';
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed;
        top: 80px;
        right: 20px;
        background: #10b981;
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

// ==================== CLEANUP ====================
window.addEventListener('beforeunload', () => {
    if (autoPlayInterval) {
        clearInterval(autoPlayInterval);
    }
    if (evalChart) {
        evalChart.destroy();
    }
});

// Add CSS animations
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

console.log('Review page initialized');