import sys
import os
import subprocess
import platform
import time
import atexit
import logging
from pathlib import Path

class APIServerManager:
    """
    Manages the SecureVault API server process.
    Launches the same executable with the '--api-server' flag.
    """
    def __init__(self, host='localhost', port=5000):
            self.host = host
            self.port = port
            self.api_url = f"https://{host}:{port}/api"
            self.server_process = None
            self.logger = logging.getLogger('api_server_manager')

    def start_server(self) -> bool:
        if self.is_server_running():
            self.logger.info("API server already running")
            return True

        try:
            self.logger.info("Starting API server using '--api-server' flag")

            # The command calls main.py with the --api-server argument
            cmd = [sys.executable, "main.py", "--api-server"]

            env = os.environ.copy()
            env.update({
                'HOST': self.host,
                'PORT': str(self.port),
                'FLASK_ENV': 'development'
            })

            self.server_process = subprocess.Popen(cmd, env=env)
            atexit.register(self.stop_server)

            # Wait up to 10 seconds
            for _ in range(10):
                if self.is_server_running():
                    self.logger.info("API server started successfully")
                    return True
                time.sleep(1)

            self.logger.error("API server failed to start")
            self.stop_server()
            return False

        except Exception as e:
            self.logger.error(f"Failed to start API server: {e}")
            return False

    def _setup_logging(self):
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

    def is_server_running(self) -> bool:
        try:
            import requests
            response = requests.get(f"{self.api_url}/files", verify=False, timeout=2)
            # A 401 response indicates the server is up (authentication required)
            return response.status_code == 401
        except Exception:
            return False

    def stop_server(self):
        if self.server_process:
            try:
                self.server_process.terminate()
                self.server_process.wait(timeout=5)
                self.logger.info("API server stopped")
            except Exception as e:
                self.logger.error(f"Error stopping API server: {e}")
                self.server_process.kill()
            finally:
                self.server_process = None