let matchSkip = 0;
const MATCHES_PER_PAGE = 5;
let hasNextPage = true;

// Load match history
async function loadMatchHistory(skip = 0) {
    try {
        const response = await fetch(
            `/api/match/history?skip=${skip}&limit=${MATCHES_PER_PAGE}`,
            { credentials: 'include' }
        );

        if (!response.ok) {
            throw new Error('Failed to load matches');
        }

        const data = await response.json();

        // Update state
        matchSkip = skip;
        hasNextPage = data.count === MATCHES_PER_PAGE;

        // Render matches
        displayMatchHistory(data.matches);

        // Update buttons
        updatePaginationButtons();

    } catch (error) {
        console.error('Error loading match history:', error);
        document.getElementById('matchHistory').innerHTML =
            '<p class="loading">Failed to load matches. Please try again.</p>';
    }
}

// Render match list
function displayMatchHistory(matches) {
    const container = document.getElementById('matchHistory');

    if (!matches || matches.length === 0) {
        container.innerHTML = '<p class="loading">No matches yet</p>';
        return;
    }

    container.innerHTML = matches.map(match => {
        const resultClass = getResultClass(match.result, match.your_color);
        const resultText = getResultText(match.result, match.your_color);

        return `
            <div class="match-item">
                <div class="match-main-info">
                    <div class="piece-color-indicator ${match.your_color.toLowerCase()}" title="You played as ${match.your_color}"></div>
                    
                    <div class="match-details">
                        <div class="opponent-row">
                            <span class="opponent-name">${match.opponent_name}</span>
                            <span class="opponent-elo">${match.opponent_elo}</span>
                        </div>
                        <div class="match-time">
                            <span>${match.start}</span>
                            <span class="time-separator">→</span>
                            <span>${match.end}</span>
                        </div>
                    </div>
                </div>

                <div class="match-status-wrapper">
                    <span class="match-result-badge ${resultClass}">
                        ${resultText}
                    </span>
                </div>
            </div>
        `;
    }).join('');
}

// Result helpers
function getResultClass(result, yourColor) {
    if (result === 'draw') return 'draw';
    if (
        (result === 'white_win' && yourColor === 'white') ||
        (result === 'black_win' && yourColor === 'black')
    ) return 'win';
    return 'loss';
}

function getResultText(result, yourColor) {
    if (result === 'draw') return 'Draw';
    if (
        (result === 'white_win' && yourColor === 'white') ||
        (result === 'black_win' && yourColor === 'black')
    ) return 'Win';
    return 'Loss';
}

// Pagination buttons
function prevPage() {
    if (matchSkip > 0) {
        loadMatchHistory(matchSkip - MATCHES_PER_PAGE);
    }
}

function nextPage() {
    if (hasNextPage) {
        loadMatchHistory(matchSkip + MATCHES_PER_PAGE);
    }
}

function updatePaginationButtons() {
    document.getElementById('prevPageBtn').disabled = matchSkip === 0;
    document.getElementById('nextPageBtn').disabled = !hasNextPage;
}
