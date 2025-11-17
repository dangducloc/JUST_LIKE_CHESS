import { Piece } from "./Piece.model.js";

export class Rook extends Piece {
    getMoves(row, col, board) {
        return this.slideMoves(row, col, board, [[1, 0], [-1, 0], [0, 1], [0, -1]]);
    }
    slideMoves(row, col, board, dirs) {
        let moves = [];
        for (let [dr, dc] of dirs) {
            let r = row + dr, c = col + dc;
            while (r >= 0 && r < 8 && c >= 0 && c < 8) {
                if (board[r][c] === null) moves.push([r, c, "move"]);
                else {
                    if (this.isEnemy(board[r][c])) moves.push([r, c, "capture"]);
                    break;
                }
                r += dr; c += dc;
            }
        }
        return moves;
    }
}

export class Bishop extends Rook {
    getMoves(row, col, board) {
        return this.slideMoves(row, col, board, [[1, 1], [1, -1], [-1, 1], [-1, -1]]);
    }
}

export class Queen extends Rook {
    getMoves(row, col, board) {
        return this.slideMoves(row, col, board, [[1, 0], [-1, 0], [0, 1], [0, -1], [1, 1], [1, -1], [-1, 1], [-1, -1]]);
    }
}
