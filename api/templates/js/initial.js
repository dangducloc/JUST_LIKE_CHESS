import { pieces } from "./model/index.model.js";

let Pawn = pieces.Pawn;
let King = pieces.King;
let Knight = pieces.Knight;
let Rook = pieces.Rook;
let Bishop = pieces.Bishop;
let Queen = pieces.Queen;

function createPiece(symbol) {
    const white = "♙♖♘♗♕♔";
    const black = "♟♜♞♝♛♚";
    if (symbol === "") return null;
    let color = white.includes(symbol) ? "white" : "black";
    switch (symbol) {
        case "♙": case "♟": return new Pawn(symbol, color);
        case "♖": case "♜": return new Rook(symbol, color);
        case "♘": case "♞": return new Knight(symbol, color);
        case "♗": case "♝": return new Bishop(symbol, color);
        case "♕": case "♛": return new Queen(symbol, color);
        case "♔": case "♚": return new King(symbol, color);
    }
}

const initial = [
    ["♜","♞","♝","♛","♚","♝","♞","♜"],
    ["♟","♟","♟","♟","♟","♟","♟","♟"],
    ["","","","","","","",""],
    ["","","","","","","",""],
    ["","","","","","","",""],
    ["","","","","","","",""],
    ["♙","♙","♙","♙","♙","♙","♙","♙"],
    ["♖","♘","♗","♕","♔","♗","♘","♖"]
];

// 👇 gói tất cả trạng thái vào object
export const state = {
    boardState: initial.map(row => row.map(s => createPiece(s))),
    board: document.getElementById("board"),
    dragged: null,
    fromCell: null,
    turn: "white",
    enPassantTarget: null,
    pgn: []
};

export function clearHighlights() {
    document.querySelectorAll(".possible-move,.possible-capture").forEach(c => {
        c.classList.remove("possible-move", "possible-capture");
    });
}
