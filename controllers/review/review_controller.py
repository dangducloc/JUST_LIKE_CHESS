# controller/review/review_controller.py
from chess import Board,engine,WHITE

from bson import ObjectId
from controllers.matchs.match_controller import get_match
from controllers.users.users_controller import get_user_by_id
from dotenv import load_dotenv, find_dotenv
import os
import logging
from typing import List, Dict, Any

load_dotenv(find_dotenv())
logger = logging.getLogger(__name__)
stockfish_path = os.getenv('STOCKFISH_PATH', '../../engine/stockfish.exe')
logger.info(f"stockfish path: {stockfish_path}")

# MAIN FUNCTION
def review_game(match_id:ObjectId)->dict|None:
    match = get_match(match_id)
    san_pgn = match.pgn
    if(san_pgn != ""):
        analysis = analyze_moves_simple(
            moves_san=san_pgn,
            engine_path=stockfish_path,
            depth=15
        )
        white = {
            "id": str(match.white),
            "username": get_user_by_id(match.white).name,
            "elo": get_user_by_id(match.white).elo,
        }
        black = {
            "id": str(match.black),
            "username": get_user_by_id(match.black).name,
            "elo": get_user_by_id(match.black).elo,
        }
        result = {
            "match_id": str(match_id),
            "white":white,
            "black": black,
            "pgn": match.pgn,
            "status": match.status,
            "move_count": len(analysis),
            "analysis": analysis,
        }
        return result
    elif san_pgn=="" and  match.status == "draw":
        logger.info(f"[!] Match {match_id} is a draw without moves.")
        white = {
            "id": str(match.white),
            "username": get_user_by_id(match.white).name,
            "elo": get_user_by_id(match.white).elo,
        }
        black = {
            "id": str(match.black),
            "username": get_user_by_id(match.black).name,
            "elo": get_user_by_id(match.black).elo,
        }
        result = {
            "match_id": str(match_id),
            "white": white,
            "black": black,
            "pgn": match.pgn,
            "status": match.status,
            "move_count": 0,
            "analysis": [],
        }
        return result

    return None

def analyze_moves_simple(
    moves_san: str,
    engine_path: str = "../engine/stockfish.exe",
    depth: int = 15
) -> List[Dict[str, Any]]:

    def format_eval(score) -> str:
        if score.is_mate():
            m = score.mate()
            return f"M{m}" if m > 0 else f"M{-m}"
        cp = score.score()
        if cp is None:
            return "0.00"
        return f"{cp/100:+.2f}"

    def classify(loss_cp: int) -> str:
        if loss_cp > 200:
            return "BLUNDER"
        if loss_cp > 100:
            return "MISTAKE"
        if loss_cp > 50:
            return "INACCURACY"
        return "OK"

    Engine = engine.SimpleEngine.popen_uci(engine_path)
    board = Board()
    results = []

    try:
        for ply, san in enumerate(moves_san.split(), start=1):
            board_before = board.copy()
            side = "white" if board.turn == WHITE else "black"

            info_before = Engine.analyse(
                board,
                engine.Limit(depth=depth),
                multipv=1
            )[0]

            score_before = info_before["score"].white()
            best_uci = info_before.get("pv", [None])[0]

            best_san = None
            if best_uci:
                try:
                    best_san = board_before.san(best_uci)
                except:
                    best_san = str(best_uci)

            board.push_san(san)

            info_after = Engine.analyse(
                board,
                engine.Limit(depth=depth)
            )

            score_after = info_after["score"].white()

            loss_cp = 0
            judgment = "OK"

            if score_before.is_mate() and not score_after.is_mate():
                judgment = "BLUNDER"
                loss_cp = 9999

            elif not score_before.is_mate() and not score_after.is_mate():
                before_cp = score_before.score()
                after_cp = score_after.score()

                if before_cp is not None and after_cp is not None:
                    if side == "white":
                        loss_cp = max(0, before_cp - after_cp)
                    else:
                        loss_cp = max(0, after_cp - before_cp)

                    judgment = classify(loss_cp)

            results.append({
                "ply": ply,
                "move": san,
                "color": side,
                "eval_before": format_eval(score_before),
                "eval_after": format_eval(score_after),
                "loss_cp": loss_cp,
                "loss": round(loss_cp / 100, 2),
                "judgment": judgment,
                "best_move": best_san,
            })

    finally:
        Engine.quit()

    return results