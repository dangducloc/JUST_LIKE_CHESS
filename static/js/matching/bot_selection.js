// Bot Selection Logic

document.addEventListener('DOMContentLoaded', () => {
    setupBotButtons();
});

function setupBotButtons() {
    const botButtons = document.querySelectorAll('.btn-play-bot');
    
    botButtons.forEach(button => {
        button.addEventListener('click', function() {
            const difficulty = this.dataset.difficulty;
            startBotMatch(difficulty);
        });
    });
}

async function startBotMatch(difficulty) {
    try {
        const validDifficulties = ['beginner', 'easy', 'medium', 'hard', 'expert'];
        if (!validDifficulties.includes(difficulty)) {
            showNotification('Invalid difficulty level', 'error');
            return;
        }
        
        showBotMatchLoading(difficulty);
        window.location.href = `/game/bot?difficulty=${difficulty}`;
        
    } catch (error) {
        console.error('Error starting bot match:', error);
        showNotification('Failed to start bot match. Please try again.', 'error');
        hideBotMatchLoading();
    }
}

function showBotMatchLoading(difficulty) {
    const botNames = {
        'beginner': 'ChessBot Junior',
        'easy': 'ChessBot Novice',
        'medium': 'ChessBot Standard',
        'hard': 'ChessBot Pro',
        'expert': 'ChessBot Master'
    };
    
    const botIcons = {
        'beginner': '🐣',
        'easy': '🐥',
        'medium': '🦅',
        'hard': '🦁',
        'expert': '👑'
    };
    
    const overlay = document.createElement('div');
    overlay.id = 'botMatchLoading';
    overlay.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.9);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 10000;
    `;
    
    overlay.innerHTML = `
        <div style="text-align: center; color: white;">
            <div style="font-size: 5rem; margin-bottom: 1rem; animation: bounce 1s infinite;">
                ${botIcons[difficulty]}
            </div>
            <h2 style="font-size: 2rem; margin-bottom: 0.5rem;">
                Starting match vs ${botNames[difficulty]}
            </h2>
            <p style="color: rgba(255, 255, 255, 0.8);">
                Preparing the board...
            </p>
            <div style="width: 60px; height: 60px; border: 5px solid rgba(255, 255, 255, 0.2); border-top: 5px solid #fff; border-radius: 50%; animation: spin 1s linear infinite; margin: 2rem auto;"></div>
        </div>
    `;
    
    document.body.appendChild(overlay);
    
    const style = document.createElement('style');
    style.textContent = `
        @keyframes bounce {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-20px); }
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    `;
    document.head.appendChild(style);
}

function hideBotMatchLoading() {
    const overlay = document.getElementById('botMatchLoading');
    if (overlay) {
        overlay.remove();
    }
}

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.textContent = message;
    
    const bgColors = {
        'info': '#3b82f6',
        'success': '#10b981',
        'error': '#ef4444',
        'warning': '#f59e0b'
    };
    
    notification.style.cssText = `
        position: fixed;
        top: 80px;
        right: 20px;
        background: ${bgColors[type] || bgColors.info};
        color: white;
        padding: 1rem 1.5rem;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.2);
        z-index: 9998;
        animation: slideInRight 0.3s ease-out;
        max-width: 300px;
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'slideOutRight 0.3s ease-out';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

console.log('✓ Bot selection initialized');