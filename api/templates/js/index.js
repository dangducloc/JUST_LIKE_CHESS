import { state, clearHighlights } from "./initial.js";
import { getPGNNotation } from "./pgn.js";

function renderBoard() {
    const { board, boardState } = state;
    board.innerHTML = "";
    console.log("🔄 Render lại bàn cờ, lượt:", state.turn);

    for (let r = 0; r < 8; r++) {
        for (let c = 0; c < 8; c++) {
            const cell = document.createElement("div");
            cell.classList.add("cell", (r + c) % 2 == 0 ? "white" : "black");
            cell.id = `cell-${r}-${c}`;
            cell.dataset.row = r;
            cell.dataset.col = c;
            cell.textContent = boardState[r][c] ? boardState[r][c].type : "";
            cell.draggable = !!boardState[r][c];

            cell.addEventListener("dragstart", e => dragstart(e, r, c, cell));
            cell.addEventListener("dragover", e => e.preventDefault());
            cell.addEventListener("drop", e => handleDrop(e, r, c));
            cell.addEventListener("dragend", () => clearHighlights());

            board.appendChild(cell);
        }
    }
}

function dragstart(e, r, c, cell) {
    let piece = state.boardState[r][c];
    if (piece && piece.color === state.turn) {
        state.dragged = piece;
        state.fromCell = cell;
        const dragImage = document.getElementById("dragImage");
        dragImage.textContent = piece.type;
        e.dataTransfer.setDragImage(dragImage, 18, 18);

        console.log(`🎯 Bắt đầu kéo ${piece.type} (${piece.color}) từ [${r},${c}]`);

        let moves = piece.getMoves(r, c, state.boardState, state.enPassantTarget);
        console.log("Các nước đi hợp lệ:", moves);

        moves.forEach(([mr, mc, type]) => {
            let target = document.getElementById(`cell-${mr}-${mc}`);
            if (target) target.classList.add(
                type === "capture" ? "possible-capture" :
                type === "en-passant" ? "possible-capture" :
                "possible-move"
            );
        });
    } else {
        e.preventDefault();
    }
}

function handleDrop(e, tr, tc) {
    e.preventDefault();
    if (state.dragged) {
        let fr = parseInt(state.fromCell.dataset.row),
            fc = parseInt(state.fromCell.dataset.col);
        let moves = state.dragged.getMoves(fr, fc, state.boardState, state.enPassantTarget);

        let move = moves.find(([mr, mc]) => mr === tr && mc === tc);
        if (move) {

            // ---  PGN  ---
            let notation = getPGNNotation(state.dragged, fr, fc, tr, tc, move);

            state.pgn.push(notation);
            console.log("📜 PGN:", state.pgn.join(" "));

            // --- En passant ---
            if (move[2] === "en-passant") {
                if (state.dragged.type === "♙") state.boardState[tr + 1][tc] = null;
                else if (state.dragged.type === "♟") state.boardState[tr - 1][tc] = null;
            }

            // --- Castling ---
            if ((state.dragged.type === "♔" || state.dragged.type === "♚") && Math.abs(tc - fc) === 2) {
                if (tc === 6) { // short castle
                    let rook = state.boardState[tr][7];
                    state.boardState[tr][5] = rook;
                    state.boardState[tr][7] = null;
                    if (rook) rook.hasMoved = true;
                }
                if (tc === 2) { // long castle
                    let rook = state.boardState[tr][0];
                    state.boardState[tr][3] = rook;
                    state.boardState[tr][0] = null;
                    if (rook) rook.hasMoved = true;
                }
            }

            // --- Di chuyển quân ---
            state.boardState[tr][tc] = state.dragged;
            state.boardState[fr][fc] = null;
            state.dragged.hasMoved = true;

            // --- Cập nhật enPassantTarget ---
            if (state.dragged.type === "♙" && fr === 6 && tr === 4) {
                state.enPassantTarget = [5, tc];
            } else if (state.dragged.type === "♟" && fr === 1 && tr === 3) {
                state.enPassantTarget = [2, tc];
            } else {
                state.enPassantTarget = null;
            }

            // --- Đổi lượt ---
            state.turn = (state.turn === "white") ? "black" : "white";
            // console.log("🔄 Đổi lượt ->", state.turn);
        } else {
            // console.log("❌ Nước đi không hợp lệ");
        }
    }
    clearHighlights();
    renderBoard();
}




renderBoard();
