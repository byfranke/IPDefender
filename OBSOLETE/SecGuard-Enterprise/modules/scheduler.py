"""
Security Scheduler Module for SecGuard Enterprise
===============================================

Automated scheduling system for security scans including:
- Cron job management
- Flexible scheduling options (daily, weekly, monthly)
- Email notification integration
- Job status monitoring
- Configuration persistence
"""

import asyncio
import json
import logging
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

try:
    import croniter
except ImportError as e:
    print(f"Missing required package: {e}")
    print("Run: pip install croniter")
    raise


@dataclass
class ScheduledJob:
    """Scheduled job information"""
    job_id: str
    job_type: str  # hunt, report, etc.
    frequency: str  # daily, weekly, monthly
    cron_expression: str
    enabled: bool
    created_date: datetime
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    command: str = ""
    email_on_completion: bool = True


class SecurityScheduler:
    """Automated security task scheduler"""
    
    def __init__(self, config_manager, logger):
        self.config = config_manager
        self.logger = logger
        self.data_dir = Path(config_manager.get('paths.data_dir'))
        self.jobs_file = self.data_dir / "scheduled_jobs.json"
        self.script_dir = Path("/usr/local/bin")
        
        # Cron expressions for different frequencies
        self.cron_expressions = {
            'daily': '0 2 * * *',      # 2:00 AM daily
            'weekly': '0 2 * * 1',     # 2:00 AM on Mondays
            'monthly': '0 2 1 * *'     # 2:00 AM on 1st of month
        }
        
        # Initialize scheduler
        self._initialize_scheduler()
    
    def _initialize_scheduler(self):
        """Initialize scheduler database and directories"""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        if not self.jobs_file.exists():
            with open(self.jobs_file, 'w') as f:
                json.dump([], f)
    
    def _load_jobs(self) -> List[Dict]:
        """Load scheduled jobs from database"""
        try:
            with open(self.jobs_file, 'r') as f:
                jobs_data = json.load(f)
                
            # Convert date strings back to datetime objects
            for job in jobs_data:
                if isinstance(job.get('created_date'), str):
                    job['created_date'] = datetime.fromisoformat(job['created_date'])
                if isinstance(job.get('last_run'), str):
                    job['last_run'] = datetime.fromisoformat(job['last_run'])
                if isinstance(job.get('next_run'), str):
                    job['next_run'] = datetime.fromisoformat(job['next_run'])
            
            return jobs_data
        
        except (json.JSONDecodeError, FileNotFoundError):
            return []
    
    def _save_jobs(self, jobs: List[Dict]):
        """Save scheduled jobs to database"""
        # Convert datetime objects to ISO format
        for job in jobs:
            for date_field in ['created_date', 'last_run', 'next_run']:
                if isinstance(job.get(date_field), datetime):
                    job[date_field] = job[date_field].isoformat()
        
        with open(self.jobs_file, 'w') as f:
            json.dump(jobs, f, indent=2, default=str)
    
    async def enable_schedule(self, scan_type: str, frequency: str, 
                            custom_time: str = None, email_notify: bool = True) -> Dict[str, Any]:
        """Enable scheduled scanning"""
        
        if frequency not in self.cron_expressions:
            return {"success": False, "error": "Invalid frequency. Use: daily, weekly, monthly"}
        
        # Check if job already exists
        jobs = self._load_jobs()
        existing_job = next((job for job in jobs if job['job_type'] == scan_type), None)
        
        if existing_job:
            return {"success": False, "error": f"Schedule for {scan_type} already exists"}
        
        # Create cron expression
        if custom_time:
            try:
                hour, minute = custom_time.split(':')
                cron_expr = f"{minute} {hour} * * *"
                if frequency == 'weekly':
                    cron_expr = f"{minute} {hour} * * 1"
                elif frequency == 'monthly':
                    cron_expr = f"{minute} {hour} 1 * *"
            except:
                cron_expr = self.cron_expressions[frequency]
        else:
            cron_expr = self.cron_expressions[frequency]
        
        # Create job
        job_id = f"secguard_{scan_type}_{frequency}"
        
        scheduled_job = ScheduledJob(
            job_id=job_id,
            job_type=scan_type,
            frequency=frequency,
            cron_expression=cron_expr,
            enabled=True,
            created_date=datetime.now(),
            email_on_completion=email_notify
        )
        
        # Generate command based on job type
        if scan_type == 'hunt':
            scheduled_job.command = self._generate_hunt_command()
        
        # Calculate next run time
        scheduled_job.next_run = self._get_next_run_time(cron_expr)
        
        # Add to system cron
        cron_result = await self._add_to_system_cron(scheduled_job)
        if not cron_result['success']:
            return cron_result
        
        # Save to database
        jobs.append(asdict(scheduled_job))
        self._save_jobs(jobs)
        
        self.logger.info(f"Enabled {frequency} {scan_type} schedule")
        
        return {
            "success": True,
            "job_id": job_id,
            "next_run": scheduled_job.next_run,
            "cron_expression": cron_expr
        }
    
    async def disable_schedule(self, scan_type: str) -> Dict[str, Any]:
        """Disable scheduled scanning"""
        jobs = self._load_jobs()
        job_to_remove = next((job for job in jobs if job['job_type'] == scan_type), None)
        
        if not job_to_remove:
            return {"success": False, "error": f"No schedule found for {scan_type}"}
        
        # Remove from system cron
        cron_result = await self._remove_from_system_cron(job_to_remove['job_id'])
        
        # Remove from database
        jobs = [job for job in jobs if job['job_type'] != scan_type]
        self._save_jobs(jobs)
        
        self.logger.info(f"Disabled {scan_type} schedule")
        
        return {
            "success": True,
            "message": f"Disabled {scan_type} schedule",
            "cron_result": cron_result
        }
    
    async def get_status(self) -> List[Dict[str, Any]]:
        """Get status of all scheduled jobs"""
        jobs = self._load_jobs()
        status_list = []
        
        for job in jobs:
            # Update next run time
            if job['enabled']:
                job['next_run'] = self._get_next_run_time(job['cron_expression'])
            
            status_list.append({
                'type': job['job_type'],
                'frequency': job['frequency'],
                'status': 'Enabled' if job['enabled'] else 'Disabled',
                'next_run': job.get('next_run'),
                'last_run': job.get('last_run'),
                'cron_expression': job['cron_expression']
            })
        
        return status_list
    
    async def run_job_now(self, scan_type: str) -> Dict[str, Any]:
        """Execute a scheduled job immediately"""
        jobs = self._load_jobs()
        job = next((j for j in jobs if j['job_type'] == scan_type), None)
        
        if not job:
            return {"success": False, "error": f"No job found for {scan_type}"}
        
        try:
            # Execute the job
            if scan_type == 'hunt':
                result = await self._execute_hunt_job(job)
            else:
                return {"success": False, "error": f"Unknown job type: {scan_type}"}
            
            # Update last run time
            for j in jobs:
                if j['job_type'] == scan_type:
                    j['last_run'] = datetime.now()
                    break
            
            self._save_jobs(jobs)
            
            return {"success": True, "result": result}
        
        except Exception as e:
            self.logger.error(f"Job execution failed for {scan_type}: {e}")
            return {"success": False, "error": str(e)}
    
    def _generate_hunt_command(self) -> str:
        """Generate command for threat hunting job"""
        script_path = self.script_dir / "secguard"
        
        # Build command with all hunting options
        cmd_parts = [
            str(script_path),
            "hunt",
            "--all",
            "--deep" if self.config.get('hunting.deep_scan') else "",
            "--report"
        ]
        
        return " ".join(filter(None, cmd_parts))
    
    def _get_next_run_time(self, cron_expression: str) -> datetime:
        """Calculate next run time from cron expression"""
        try:
            from croniter import croniter
            now = datetime.now()
            cron = croniter(cron_expression, now)
            return cron.get_next(datetime)
        except ImportError:
            # Fallback calculation without croniter
            return datetime.now() + timedelta(hours=24)
        except:
            return datetime.now() + timedelta(hours=24)
    
    async def _add_to_system_cron(self, job: ScheduledJob) -> Dict[str, Any]:
        """Add job to system crontab"""
        try:
            # Create wrapper script for the job
            wrapper_script = await self._create_job_wrapper(job)
            
            # Add to crontab
            cron_line = f"{job.cron_expression} {wrapper_script}"
            
            # Get current crontab
            try:
                result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
                current_cron = result.stdout if result.returncode == 0 else ""
            except:
                current_cron = ""
            
            # Add new job if not already present
            if job.job_id not in current_cron:
                new_cron = current_cron + f"\n# SecGuard Job: {job.job_id}\n{cron_line}\n"
                
                # Write new crontab
                process = subprocess.Popen(['crontab', '-'], stdin=subprocess.PIPE, text=True)
                process.communicate(input=new_cron)
                
                if process.returncode == 0:
                    return {"success": True, "message": "Added to system cron"}
                else:
                    return {"success": False, "error": "Failed to update crontab"}
            else:
                return {"success": True, "message": "Job already exists in crontab"}
        
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _remove_from_system_cron(self, job_id: str) -> Dict[str, Any]:
        """Remove job from system crontab"""
        try:
            # Get current crontab
            result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
            
            if result.returncode != 0:
                return {"success": True, "message": "No crontab to modify"}
            
            current_cron = result.stdout
            lines = current_cron.split('\n')
            
            # Filter out lines related to this job
            filtered_lines = []
            skip_next = False
            
            for line in lines:
                if f"SecGuard Job: {job_id}" in line:
                    skip_next = True
                    continue
                
                if skip_next and (job_id in line or line.strip() == ""):
                    skip_next = False
                    continue
                
                filtered_lines.append(line)
            
            # Write updated crontab
            new_cron = '\n'.join(filtered_lines)
            process = subprocess.Popen(['crontab', '-'], stdin=subprocess.PIPE, text=True)
            process.communicate(input=new_cron)
            
            # Remove wrapper script
            wrapper_path = Path(f"/tmp/secguard_wrapper_{job_id}.sh")
            if wrapper_path.exists():
                wrapper_path.unlink()
            
            return {"success": True, "message": "Removed from system cron"}
        
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _create_job_wrapper(self, job: ScheduledJob) -> str:
        """Create wrapper script for scheduled job"""
        wrapper_path = Path(f"/tmp/secguard_wrapper_{job.job_id}.sh")
        
        wrapper_content = f"""#!/bin/bash
# SecGuard Scheduled Job Wrapper
# Job ID: {job.job_id}
# Job Type: {job.job_type}
# Created: {job.created_date}

LOG_FILE="/var/log/secguard/scheduled_{job.job_type}.log"
LOCK_FILE="/tmp/secguard_{job.job_id}.lock"

# Check for lock file to prevent overlapping runs
if [ -f "$LOCK_FILE" ]; then
    echo "$(date): Job already running, skipping" >> "$LOG_FILE"
    exit 0
fi

# Create lock file
touch "$LOCK_FILE"

# Execute the job
echo "$(date): Starting scheduled {job.job_type}" >> "$LOG_FILE"
{job.command} >> "$LOG_FILE" 2>&1
EXIT_CODE=$?

# Log completion
echo "$(date): Completed scheduled {job.job_type} (exit code: $EXIT_CODE)" >> "$LOG_FILE"

# Send email notification if configured
if [ "{job.email_on_completion}" = "True" ] && [ -x "/usr/local/bin/secguard" ]; then
    if [ $EXIT_CODE -eq 0 ]; then
        echo "Scheduled {job.job_type} completed successfully" | /usr/local/bin/secguard notify-email "SecGuard Schedule: {job.job_type} Completed" || true
    else
        echo "Scheduled {job.job_type} failed with exit code $EXIT_CODE" | /usr/local/bin/secguard notify-email "SecGuard Schedule: {job.job_type} Failed" || true
    fi
fi

# Remove lock file
rm -f "$LOCK_FILE"

exit $EXIT_CODE
"""
        
        # Write wrapper script
        with open(wrapper_path, 'w') as f:
            f.write(wrapper_content)
        
        # Make executable
        wrapper_path.chmod(0o755)
        
        return str(wrapper_path)
    
    async def _execute_hunt_job(self, job: Dict) -> Dict[str, Any]:
        """Execute threat hunting job"""
        try:
            # Import here to avoid circular imports
            from threat_hunter import ThreatHunter
            
            hunter = ThreatHunter(self.config, self.logger)
            
            # Execute full scan
            results = await hunter.full_scan(
                check_services=True,
                check_users=True,
                check_persistence=True,
                check_network=True,
                deep_scan=self.config.get('hunting.deep_scan', False)
            )
            
            return {
                "scan_completed": True,
                "summary": results.get('summary', {}),
                "timestamp": datetime.now().isoformat()
            }
        
        except Exception as e:
            raise Exception(f"Hunt job execution failed: {e}")
    
    async def update_job_schedule(self, scan_type: str, new_frequency: str, 
                                 custom_time: str = None) -> Dict[str, Any]:
        """Update existing job schedule"""
        # Disable current schedule
        disable_result = await self.disable_schedule(scan_type)
        
        if not disable_result['success']:
            return disable_result
        
        # Enable with new schedule
        return await self.enable_schedule(scan_type, new_frequency, custom_time)
    
    async def get_job_logs(self, scan_type: str, lines: int = 50) -> Dict[str, Any]:
        """Get recent logs for a scheduled job"""
        log_file = Path(f"/var/log/secguard/scheduled_{scan_type}.log")
        
        if not log_file.exists():
            return {"success": False, "error": "Log file not found"}
        
        try:
            # Use tail command to get last N lines
            result = subprocess.run(['tail', '-n', str(lines), str(log_file)], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                return {
                    "success": True,
                    "logs": result.stdout,
                    "log_file": str(log_file)
                }
            else:
                return {"success": False, "error": "Failed to read log file"}
        
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def cleanup_old_jobs(self, days_old: int = 30) -> Dict[str, Any]:
        """Clean up old job records and logs"""
        cutoff_date = datetime.now() - timedelta(days=days_old)
        
        # Clean up old job records
        jobs = self._load_jobs()
        original_count = len(jobs)
        
        # Keep only recent jobs or enabled jobs
        jobs = [job for job in jobs if 
                job['enabled'] or 
                (job.get('created_date') and 
                 isinstance(job['created_date'], datetime) and 
                 job['created_date'] > cutoff_date)]
        
        removed_jobs = original_count - len(jobs)
        self._save_jobs(jobs)
        
        # Clean up old log files (implement log rotation)
        log_dir = Path("/var/log/secguard")
        cleaned_logs = 0
        
        if log_dir.exists():
            for log_file in log_dir.glob("scheduled_*.log"):
                try:
                    stat = log_file.stat()
                    file_age = datetime.fromtimestamp(stat.st_mtime)
                    
                    if file_age < cutoff_date:
                        # Archive old log instead of deleting
                        archive_name = f"{log_file.name}.{file_age.strftime('%Y%m%d')}.gz"
                        archive_path = log_dir / "archive" / archive_name
                        
                        archive_path.parent.mkdir(exist_ok=True)
                        
                        # Compress and archive
                        subprocess.run(['gzip', '-c', str(log_file)], 
                                     stdout=open(archive_path, 'wb'))
                        log_file.unlink()
                        cleaned_logs += 1
                
                except Exception as e:
                    self.logger.warning(f"Failed to clean log {log_file}: {e}")
        
        return {
            "success": True,
            "removed_jobs": removed_jobs,
            "archived_logs": cleaned_logs
        }
