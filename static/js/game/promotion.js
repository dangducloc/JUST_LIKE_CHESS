// ==================== PROMOTION MODULE (FIXED) ====================
let promotionSource = null;
let promotionTarget = null;
let promotionCallback = null;

// ==================== CHECK IF MOVE IS PROMOTION ====================
function isPromotionMove(source, target) {
    // Get piece at source square
    const piece = game.get(source);
    
    if (!piece) return false;
    
    // Check if it's a pawn
    if (piece.type !== 'p') return false;
    
    // Check if moving to last rank
    const targetRank = target[1];
    const isWhitePromotion = piece.color === 'w' && targetRank === '8';
    const isBlackPromotion = piece.color === 'b' && targetRank === '1';
    
    return isWhitePromotion || isBlackPromotion;
}

// ==================== SHOW PROMOTION MODAL ====================
function showPromotionModal(source, target, callback) {
    promotionSource = source;
    promotionTarget = target;
    promotionCallback = callback;
    
    const modal = document.getElementById('promotionModal');
    const piece = game.get(source);
    
    // Update button icons based on color
    updatePromotionPieces(piece.color);
    
    modal.classList.remove('hidden');
}

function updatePromotionPieces(color) {
    const pieces = {
        'q': { white: '♕', black: '♛', name: 'Queen' },
        'r': { white: '♖', black: '♜', name: 'Rook' },
        'b': { white: '♗', black: '♝', name: 'Bishop' },
        'n': { white: '♘', black: '♞', name: 'Knight' }
    };
    
    document.querySelectorAll('#promotionModal button[data-piece]').forEach(btn => {
        const pieceType = btn.dataset.piece;
        const pieceData = pieces[pieceType];
        btn.textContent = color === 'w' ? pieceData.white : pieceData.black;
        btn.title = pieceData.name;
    });
}

function hidePromotionModal() {
    document.getElementById('promotionModal').classList.add('hidden');
    promotionSource = null;
    promotionTarget = null;
    promotionCallback = null;
}

// ==================== HANDLE PROMOTION SELECTION ====================
function handlePromotionChoice(pieceType) {
    if (!promotionSource || !promotionTarget) return;
    
    // Execute the promotion callback
    if (promotionCallback) {
        promotionCallback(pieceType);
    }
    
    hidePromotionModal();
}

// ==================== INIT PROMOTION HANDLERS ====================
function initPromotionHandlers() {
    const buttons = document.querySelectorAll('#promotionModal button[data-piece]');
    
    buttons.forEach(btn => {
        btn.addEventListener('click', () => {
            const piece = btn.dataset.piece;
            handlePromotionChoice(piece);
        });
    });
    
    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        const modal = document.getElementById('promotionModal');
        if (modal.classList.contains('hidden')) return;
        
        const key = e.key.toLowerCase();
        const pieceMap = { 'q': 'q', 'r': 'r', 'b': 'b', 'n': 'n' };
        
        if (pieceMap[key]) {
            e.preventDefault();
            handlePromotionChoice(pieceMap[key]);
        } else if (e.key === 'Escape') {
            e.preventDefault();
            handlePromotionChoice('q'); // Default to Queen on ESC
        }
    });
}