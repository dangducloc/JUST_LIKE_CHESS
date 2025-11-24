import { Piece } from "./Piece.model.js";

export class Pawn extends Piece {
    getMoves(row, col, board, enPassantTarget = null) {
        let moves = [];
        let dir = this.color === "white" ? -1 : 1;
        let startRow = this.color === "white" ? 6 : 1;

        // straight move
        if (board[row + dir] && board[row + dir][col] === null)
            moves.push([row + dir, col, "move"]);

        // long move
        if (row === startRow &&
            board[row + dir][col] === null &&
            board[row + 2 * dir][col] === null) {
            moves.push([row + 2 * dir, col, "move"]);
        }

        // capture + en passant
        for (let dc of [-1, 1]) {
            let nc = col + dc, nr = row + dir;
            if (board[nr] && board[nr][nc] && this.isEnemy(board[nr][nc])) {
                moves.push([nr, nc, "capture"]);
            }
            if (enPassantTarget && enPassantTarget[0] === nr && enPassantTarget[1] === nc) {
                moves.push([nr, nc, "en-passant"]);
            }
        }
        return moves;
    }
}

export class Knight extends Piece {
    getMoves(row, col, board) {
        let moves = [];
        let steps = [[2, 1], [2, -1], [-2, 1], [-2, -1], [1, 2], [1, -2], [-1, 2], [-1, -2]];
        for (let [dr, dc] of steps) {
            let r = row + dr, c = col + dc;
            if (r >= 0 && r < 8 && c >= 0 && c < 8) {
                if (board[r][c] === null) moves.push([r, c, "move"]);
                else if (this.isEnemy(board[r][c])) moves.push([r, c, "capture"]);
            }
        }
        return moves;
    }
}

export class King extends Piece {
    getMoves(row, col, board) {
        let moves = [];
        for (let dr = -1; dr <= 1; dr++) {
            for (let dc = -1; dc <= 1; dc++) {
                if (dr === 0 && dc === 0) continue;
                let r = row + dr, c = col + dc;
                if (r >= 0 && r < 8 && c >= 0 && c < 8) {
                    if (board[r][c] === null) moves.push([r, c, "move"]);
                    else if (this.isEnemy(board[r][c])) moves.push([r, c, "capture"]);
                }
            }
        }
        // castling
        moves.push(...this.castling(row, col, board));
        return moves;
    }

    castling(row, col, board) {
        let moves = [];
        if (this.hasMoved) return moves;

        let backRank = this.color === "white" ? 7 : 0;
        if (row !== backRank || col !== 4) return moves;

        // kingside
        let rookK = board[backRank][7];
        if (rookK && (rookK.type === "♖" || rookK.type === "♜")) {
            if (!rookK.hasMoved &&
                board[backRank][5] === null &&
                board[backRank][6] === null) {
                moves.push([backRank, 6, "castle-kingside"]);
            }
        }

        // queenside
        let rookQ = board[backRank][0];
        if (rookQ && (rookQ.type === "♖" || rookQ.type === "♜")) {
            if (!rookQ.hasMoved &&
                board[backRank][1] === null &&
                board[backRank][2] === null &&
                board[backRank][3] === null) {
                moves.push([backRank, 2, "castle-queenside"]);
            }
        }
        return moves;
    }
}
