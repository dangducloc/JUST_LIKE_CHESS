
export class Piece {
    constructor(type, color) {
        this.type = type;
        this.color = color;
        this.hasMoved = false;
    }
    getMoves(row, col, board) {
        return [];
    }
    isEnemy(other) {
        return other && other.color !== this.color;
    }
}


