import sys

with open("dksec/web/server.py", "r") as f:
    content = f.read()

stream_endpoint = """
        elif path == "/api/metadata":
            self._serve_json(STAGE_METADATA)
        elif path == "/api/scan/stream":
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Connection', 'keep-alive')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()

            last_log_idx = 0
            import time
            while True:
                if len(CURRENT_RUN["logs"]) > last_log_idx:
                    for i in range(last_log_idx, len(CURRENT_RUN["logs"])):
                        log = CURRENT_RUN["logs"][i]
                        self.wfile.write(f"data: {json.dumps(log)}\\n\\n".encode("utf-8"))
                        self.wfile.flush()
                    last_log_idx = len(CURRENT_RUN["logs"])
                
                if not CURRENT_RUN["running"] and last_log_idx == len(CURRENT_RUN["logs"]):
                    self.wfile.write(f"data: {json.dumps({'event': 'completed'})}\\n\\n".encode("utf-8"))
                    self.wfile.flush()
                    break
                
                time.sleep(1)
            return
"""

content = content.replace(
    """        elif path == "/api/metadata":
            self._serve_json(STAGE_METADATA)""",
    stream_endpoint
)

with open("dksec/web/server.py", "w") as f:
    f.write(content)
