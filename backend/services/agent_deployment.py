"""
Agent Deployment Service
========================
Pushes the unified Seraph Defender agent to discovered devices.

Supports:
- SSH deployment (Linux/macOS)
- WinRM deployment (Windows)
- PSExec fallback (Windows)
- WMI deployment (Windows)

The service maintains a deployment queue and handles retries.
"""
import asyncio
import logging
import os
import base64
import tempfile
from datetime import datetime, timezone
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class DeploymentMethod(str, Enum):
    SSH = "ssh"
    WINRM = "winrm"
    PSEXEC = "psexec"
    WMI = "wmi"
    MANUAL = "manual"


@dataclass
class DeploymentTask:
    device_ip: str
    device_hostname: Optional[str]
    os_type: str
    method: DeploymentMethod
    credentials: Optional[Dict] = None
    status: str = "pending"
    attempts: int = 0
    max_attempts: int = 3
    error_message: Optional[str] = None
    created_at: str = None
    completed_at: Optional[str] = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now(timezone.utc).isoformat()


class AgentDeploymentService:
    """
    Service for deploying Seraph Defender agents to discovered devices.
    Uses push-based deployment via SSH/WinRM.
    """
    
    def __init__(self, db, api_url: str):
        self.db = db
        self.api_url = api_url
        self.deployment_queue: asyncio.Queue = asyncio.Queue()
        self.running = False
        self.task = None
        self.concurrent_deployments = 5
        
        # Agent script path
        self.agent_script_path = Path("/app/scripts/seraph_defender.py")
        
        # Default credentials (should be configured via settings)
        self.default_credentials = {
            "ssh": {
                "username": "root",
                "key_path": os.path.expanduser("~/.ssh/id_rsa"),
                "password": None
            },
            "winrm": {
                "username": "Administrator",
                "password": None
            }
        }
        
        logger.info("Agent Deployment Service initialized")
    
    async def start(self):
        """Start the deployment service"""
        if self.running:
            return
        
        self.running = True
        self.task = asyncio.create_task(self._deployment_worker())
        logger.info("Agent Deployment Service started")
    
    async def stop(self):
        """Stop the deployment service"""
        self.running = False
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass
        logger.info("Agent Deployment Service stopped")
    
    async def _deployment_worker(self):
        """Worker that processes deployment tasks"""
        workers = [
            asyncio.create_task(self._process_deployments())
            for _ in range(self.concurrent_deployments)
        ]
        
        try:
            await asyncio.gather(*workers)
        except asyncio.CancelledError:
            for w in workers:
                w.cancel()
    
    async def _process_deployments(self):
        """Process deployment tasks from the queue"""
        while self.running:
            try:
                task = await asyncio.wait_for(
                    self.deployment_queue.get(),
                    timeout=5.0
                )
                
                await self._deploy_agent(task)
                self.deployment_queue.task_done()
                
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Deployment worker error: {e}")
    
    async def queue_deployment(
        self,
        device_ip: str,
        device_hostname: Optional[str],
        os_type: str,
        credentials: Optional[Dict] = None
    ) -> DeploymentTask:
        """Queue a device for agent deployment"""
        
        # Determine deployment method
        if os_type in ('linux', 'macos'):
            method = DeploymentMethod.SSH
        elif os_type == 'windows':
            method = DeploymentMethod.WINRM
        else:
            method = DeploymentMethod.MANUAL
        
        task = DeploymentTask(
            device_ip=device_ip,
            device_hostname=device_hostname,
            os_type=os_type,
            method=method,
            credentials=credentials
        )
        
        # Store in database
        await self.db.deployment_tasks.insert_one({
            "device_ip": task.device_ip,
            "device_hostname": task.device_hostname,
            "os_type": task.os_type,
            "method": task.method.value,
            "status": task.status,
            "attempts": task.attempts,
            "created_at": task.created_at
        })
        
        # Update device status
        await self.db.discovered_devices.update_one(
            {"ip_address": device_ip},
            {"$set": {"deployment_status": "queued"}}
        )
        
        # Add to queue
        await self.deployment_queue.put(task)
        
        logger.info(f"Queued deployment for {device_ip} ({os_type}) via {method.value}")
        return task
    
    async def _deploy_agent(self, task: DeploymentTask):
        """Deploy agent to a device"""
        task.attempts += 1
        task.status = "deploying"
        
        # Update database
        await self.db.deployment_tasks.update_one(
            {"device_ip": task.device_ip},
            {"$set": {"status": "deploying", "attempts": task.attempts}}
        )
        await self.db.discovered_devices.update_one(
            {"ip_address": task.device_ip},
            {"$set": {"deployment_status": "deploying"}}
        )
        
        try:
            if task.method == DeploymentMethod.SSH:
                success = await self._deploy_via_ssh(task)
            elif task.method == DeploymentMethod.WINRM:
                success = await self._deploy_via_winrm(task)
            else:
                success = False
                task.error_message = f"Unsupported deployment method: {task.method}"
            
            if success:
                task.status = "deployed"
                task.completed_at = datetime.now(timezone.utc).isoformat()
                
                await self.db.deployment_tasks.update_one(
                    {"device_ip": task.device_ip},
                    {"$set": {"status": "deployed", "completed_at": task.completed_at}}
                )
                await self.db.discovered_devices.update_one(
                    {"ip_address": task.device_ip},
                    {"$set": {"deployment_status": "deployed", "is_managed": True}}
                )
                
                logger.info(f"Successfully deployed agent to {task.device_ip}")
            else:
                raise Exception(task.error_message or "Deployment failed")
                
        except Exception as e:
            task.error_message = str(e)
            
            if task.attempts < task.max_attempts:
                task.status = "pending"
                await self.deployment_queue.put(task)
                logger.warning(f"Deployment to {task.device_ip} failed (attempt {task.attempts}), retrying...")
            else:
                task.status = "failed"
                await self.db.deployment_tasks.update_one(
                    {"device_ip": task.device_ip},
                    {"$set": {"status": "failed", "error_message": task.error_message}}
                )
                await self.db.discovered_devices.update_one(
                    {"ip_address": task.device_ip},
                    {"$set": {"deployment_status": "failed"}}
                )
                logger.error(f"Deployment to {task.device_ip} failed permanently: {e}")
    
    async def _deploy_via_ssh(self, task: DeploymentTask) -> bool:
        """Deploy agent via SSH using paramiko"""
        creds = task.credentials or self.default_credentials.get('ssh', {})
        username = creds.get('username', 'root')
        key_path = creds.get('key_path')
        password = creds.get('password')
        port = creds.get('port', 22)
        
        # Read agent script
        if not self.agent_script_path.exists():
            task.error_message = "Agent script not found"
            return False
        
        agent_code = self.agent_script_path.read_text()
        agent_b64 = base64.b64encode(agent_code.encode()).decode()
        
        # Commands to execute on remote host
        remote_commands = f'''
set -e
mkdir -p /opt/seraph-defender
echo "{agent_b64}" | base64 -d > /opt/seraph-defender/seraph_defender.py
chmod +x /opt/seraph-defender/seraph_defender.py

# Install dependencies
pip3 install psutil requests 2>/dev/null || pip install psutil requests 2>/dev/null || apt-get install -y python3-pip && pip3 install psutil requests || true

# Create systemd service
cat > /etc/systemd/system/seraph-defender.service << 'EOF'
[Unit]
Description=Seraph Defender Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/seraph-defender/seraph_defender.py --monitor --api-url {self.api_url}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable seraph-defender
systemctl start seraph-defender
echo "SERAPH_DEPLOY_SUCCESS"
'''
        
        try:
            import paramiko
            
            loop = asyncio.get_event_loop()
            
            def execute_ssh():
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                connect_kwargs = {
                    'hostname': task.device_ip,
                    'port': port,
                    'username': username,
                    'timeout': 30,
                    'allow_agent': False,
                    'look_for_keys': False
                }
                
                # Try key-based auth first, then password
                if key_path and os.path.exists(key_path):
                    try:
                        private_key = paramiko.RSAKey.from_private_key_file(key_path)
                        connect_kwargs['pkey'] = private_key
                    except Exception:
                        # Try as other key types
                        try:
                            private_key = paramiko.Ed25519Key.from_private_key_file(key_path)
                            connect_kwargs['pkey'] = private_key
                        except Exception:
                            if password:
                                connect_kwargs['password'] = password
                elif password:
                    connect_kwargs['password'] = password
                else:
                    # Allow looking for default keys
                    connect_kwargs['look_for_keys'] = True
                    connect_kwargs['allow_agent'] = True
                
                try:
                    client.connect(**connect_kwargs)
                except paramiko.AuthenticationException as e:
                    return False, f"Authentication failed: {e}"
                except Exception as e:
                    return False, f"Connection failed: {e}"
                
                try:
                    stdin, stdout, stderr = client.exec_command(remote_commands, timeout=120)
                    exit_code = stdout.channel.recv_exit_status()
                    output = stdout.read().decode() + stderr.read().decode()
                    
                    client.close()
                    
                    if 'SERAPH_DEPLOY_SUCCESS' in output:
                        return True, output
                    else:
                        return False, f"Deployment commands failed (exit {exit_code}): {output[-500:]}"
                        
                except Exception as e:
                    client.close()
                    return False, f"Command execution failed: {e}"
            
            success, message = await loop.run_in_executor(None, execute_ssh)
            
            if not success:
                task.error_message = message
                return False
            
            return True
            
        except ImportError:
            # Fall back to subprocess-based SSH
            logger.warning("paramiko not installed, falling back to subprocess SSH")
            return await self._deploy_via_ssh_subprocess(task, username, key_path, password, remote_commands)
            
        except Exception as e:
            task.error_message = f"SSH error: {str(e)}"
            return False
    
    async def _deploy_via_ssh_subprocess(self, task: DeploymentTask, username: str, key_path: str, password: str, remote_commands: str) -> bool:
        """Fallback SSH deployment using subprocess"""
        ssh_opts = ['-o', 'StrictHostKeyChecking=no', '-o', 'ConnectTimeout=30', '-o', 'BatchMode=yes']
        
        if key_path and os.path.exists(key_path):
            ssh_opts.extend(['-i', key_path])
        
        try:
            if password:
                proc = await asyncio.create_subprocess_exec(
                    'sshpass', '-p', password,
                    'ssh', *ssh_opts, f'{username}@{task.device_ip}',
                    'bash', '-c', remote_commands,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
            else:
                proc = await asyncio.create_subprocess_exec(
                    'ssh', *ssh_opts, f'{username}@{task.device_ip}',
                    'bash', '-c', remote_commands,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
            
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
            output = stdout.decode() + stderr.decode()
            
            if 'SERAPH_DEPLOY_SUCCESS' in output:
                return True
            else:
                task.error_message = f"SSH deployment failed: {output[-500:]}"
                return False
                
        except asyncio.TimeoutError:
            task.error_message = "SSH connection timed out"
            return False
        except Exception as e:
            task.error_message = f"SSH subprocess error: {str(e)}"
            return False
    
    async def _deploy_via_winrm(self, task: DeploymentTask) -> bool:
        """Deploy agent via WinRM"""
        creds = task.credentials or self.default_credentials.get('winrm', {})
        username = creds.get('username', 'Administrator')
        password = creds.get('password')
        
        if not password:
            task.error_message = "WinRM requires password authentication"
            return False
        
        # Read agent script
        if not self.agent_script_path.exists():
            task.error_message = "Agent script not found"
            return False
        
        agent_code = self.agent_script_path.read_text()
        agent_b64 = base64.b64encode(agent_code.encode()).decode()
        
        # PowerShell commands
        ps_script = f'''
$ErrorActionPreference = "Stop"

# Create directory
New-Item -ItemType Directory -Force -Path "C:\\SeraphDefender" | Out-Null

# Decode and write agent
$agentB64 = "{agent_b64}"
$agentBytes = [System.Convert]::FromBase64String($agentB64)
[System.IO.File]::WriteAllBytes("C:\\SeraphDefender\\seraph_defender.py", $agentBytes)

# Install Python if not present
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {{
    Write-Host "Python not found, attempting to install..."
    # Download Python installer
    Invoke-WebRequest -Uri "https://www.python.org/ftp/python/3.11.0/python-3.11.0-amd64.exe" -OutFile "$env:TEMP\\python_installer.exe"
    Start-Process -FilePath "$env:TEMP\\python_installer.exe" -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1" -Wait
}}

# Install dependencies
python -m pip install psutil requests --quiet

# Create scheduled task to run agent
$action = New-ScheduledTaskAction -Execute "python" -Argument "C:\\SeraphDefender\\seraph_defender.py --monitor --api-url {self.api_url}"
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName "SeraphDefender" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force

# Start immediately
Start-ScheduledTask -TaskName "SeraphDefender"

Write-Host "SERAPH_DEPLOY_SUCCESS"
'''
        
        try:
            # Use pywinrm if available
            try:
                import winrm
                
                session = winrm.Session(
                    f'http://{task.device_ip}:5985/wsman',
                    auth=(username, password),
                    transport='ntlm'
                )
                
                result = session.run_ps(ps_script)
                output = result.std_out.decode() + result.std_err.decode()
                
                if 'SERAPH_DEPLOY_SUCCESS' in output:
                    return True
                else:
                    task.error_message = f"WinRM deployment failed: {output[-500:]}"
                    return False
                    
            except ImportError:
                # Fall back to PowerShell remoting via SSH if pywinrm not available
                task.error_message = "pywinrm not installed. Install with: pip install pywinrm"
                return False
                
        except Exception as e:
            task.error_message = f"WinRM error: {str(e)}"
            return False
    
    async def get_deployment_status(self, device_ip: Optional[str] = None) -> List[Dict]:
        """Get deployment task status"""
        query = {}
        if device_ip:
            query["device_ip"] = device_ip
        
        cursor = self.db.deployment_tasks.find(query, {"_id": 0})
        return await cursor.to_list(100)
    
    async def retry_failed_deployments(self):
        """Retry all failed deployments"""
        cursor = self.db.deployment_tasks.find({"status": "failed"})
        tasks = await cursor.to_list(100)
        
        for task_doc in tasks:
            task = DeploymentTask(
                device_ip=task_doc["device_ip"],
                device_hostname=task_doc.get("device_hostname"),
                os_type=task_doc["os_type"],
                method=DeploymentMethod(task_doc["method"]),
                attempts=0  # Reset attempts
            )
            
            await self.db.deployment_tasks.update_one(
                {"device_ip": task.device_ip},
                {"$set": {"status": "pending", "attempts": 0}}
            )
            
            await self.deployment_queue.put(task)
        
        return len(tasks)
    
    def set_credentials(self, method: str, credentials: Dict):
        """Set default credentials for a deployment method"""
        self.default_credentials[method] = credentials


# Global instance
_deployment_service: AgentDeploymentService = None


def get_deployment_service() -> AgentDeploymentService:
    return _deployment_service


async def start_deployment_service(db, api_url: str):
    global _deployment_service
    if _deployment_service is not None:
        await _deployment_service.stop()
    
    _deployment_service = AgentDeploymentService(db, api_url)
    await _deployment_service.start()
    return _deployment_service


async def stop_deployment_service():
    global _deployment_service
    if _deployment_service is not None:
        await _deployment_service.stop()
        _deployment_service = None
