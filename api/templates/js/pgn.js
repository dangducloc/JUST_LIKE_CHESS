import { state } from "./initial.js";


export function getPGNNotation(piece, fr, fc, tr, tc, move) {
    const files = "abcdefgh";
    let from = files[fc] + (8 - fr); // e2
    let to = files[tc] + (8 - tr);   // e4
    let capture = state.boardState[tr][tc] ? "x" : "";

    // Castling
    if (move[2] === "castle-kingside") return "O-O";
    if (move[2] === "castle-queenside") return "O-O-O";

    
    let symbol = "";
    switch (piece.type) {
        case "♙": case "♟": symbol = ""; break; 
        case "♘": case "♞": symbol = "N"; break;
        case "♗": case "♝": symbol = "B"; break;
        case "♖": case "♜": symbol = "R"; break;
        case "♕": case "♛": symbol = "Q"; break;
        case "♔": case "♚": symbol = "K"; break;
    }

    // Pawn move
    if (symbol === "") {
        if (capture) return from[0] + "x" + to; // exd5
        return to; // e4
    }

    // Normal piece move
    return symbol + (capture ? "x" : "") + to;
}