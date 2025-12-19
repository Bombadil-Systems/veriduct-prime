#!/usr/bin/env python3
"""
Veriduct Sentinel - Detects Veriduct artifacts in SQLite databases.
"""

import sqlite3
import argparse
import sys
from pathlib import Path

def check_database(db_path: Path) -> tuple[str, list[str]]:
    """
    Check if a database contains Veriduct artifacts.
    
    Returns:
        (verdict, reasons)
    """
    reasons = []
    
    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        
        # Check for chunks table
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='chunks'")
        if not cursor.fetchone():
            conn.close()
            return "clean", []
        
        reasons.append("Table 'chunks' exists")
        
        # Check columns
        cursor.execute("PRAGMA table_info(chunks)")
        columns = {row[1].lower() for row in cursor.fetchall()}
        
        if "is_fake" in columns:
            reasons.append("Column 'is_fake' exists (Veriduct signature)")
            conn.close()
            return "veriduct", reasons
        
        if "hash" in columns and "data" in columns:
            reasons.append("Has 'hash' and 'data' columns")
            conn.close()
            return "suspicious", reasons
        
        conn.close()
        return "clean", reasons
        
    except sqlite3.Error as e:
        return "error", [str(e)]
    except Exception as e:
        return "error", [str(e)]


def main():
    parser = argparse.ArgumentParser(description="Detect Veriduct artifacts")
    parser.add_argument("files", nargs="+", help="Database files to scan")
    parser.add_argument("-q", "--quiet", action="store_true", help="Only output verdicts")
    args = parser.parse_args()
    
    exit_code = 0
    
    for filepath in args.files:
        path = Path(filepath)
        
        if not path.exists():
            print(f"{filepath}: not found")
            continue
            
        verdict, reasons = check_database(path)
        
        if verdict == "veriduct":
            exit_code = 2
        elif verdict == "suspicious" and exit_code < 2:
            exit_code = 1
        
        if args.quiet:
            print(f"{filepath}: {verdict}")
        else:
            print(f"\n{filepath}")
            print(f"  Verdict: {verdict.upper()}")
            for reason in reasons:
                print(f"  - {reason}")
    
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
