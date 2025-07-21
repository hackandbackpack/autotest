"""Terminal User Interface for AutoTest progress tracking"""

import asyncio
import curses
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import threading
from dataclasses import dataclass, field
from enum import Enum
import signal
import sys


class TaskStatus(Enum):
    """Status of a task"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class TaskInfo:
    """Information about a task"""
    name: str
    status: TaskStatus = TaskStatus.PENDING
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    progress: int = 0
    max_progress: int = 100
    message: str = ""
    error: Optional[str] = None
    subtasks: List['TaskInfo'] = field(default_factory=list)
    
    @property
    def elapsed_time(self) -> str:
        """Get elapsed time as string"""
        if self.start_time is None:
            return "00:00"
        
        end = self.end_time or time.time()
        elapsed = int(end - self.start_time)
        return f"{elapsed // 60:02d}:{elapsed % 60:02d}"
    
    @property
    def is_complete(self) -> bool:
        """Check if task is complete"""
        return self.status in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.SKIPPED]


class AutoTestTUI:
    """Terminal User Interface for AutoTest"""
    
    def __init__(self):
        self.stdscr = None
        self.tasks: Dict[str, TaskInfo] = {}
        self.log_messages: List[Tuple[str, str]] = []  # (timestamp, message)
        self.max_log_messages = 100
        self.running = False
        self.lock = threading.Lock()
        self.start_time = None
        self.total_targets = 0
        self.completed_targets = 0
        self.current_target = ""
        self.ui_thread = None
        self._shutdown_event = threading.Event()
        
    def start(self):
        """Start the TUI in a separate thread"""
        self.running = True
        self.start_time = time.time()
        self.ui_thread = threading.Thread(target=self._run_ui, daemon=True)
        self.ui_thread.start()
        
    def stop(self):
        """Stop the TUI"""
        self.running = False
        self._shutdown_event.set()
        if self.ui_thread:
            self.ui_thread.join(timeout=2)
        if self.stdscr:
            curses.endwin()
            
    def _run_ui(self):
        """Run the UI loop"""
        try:
            curses.wrapper(self._ui_main)
        except Exception:
            # Ignore errors on shutdown
            pass
            
    def _ui_main(self, stdscr):
        """Main UI function"""
        self.stdscr = stdscr
        curses.curs_set(0)  # Hide cursor
        stdscr.nodelay(True)  # Non-blocking input
        
        # Initialize colors
        curses.start_color()
        curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(4, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_BLACK)
        
        while self.running and not self._shutdown_event.is_set():
            try:
                self._draw_ui()
                
                # Check for input
                key = stdscr.getch()
                if key == ord('q'):
                    self.running = False
                    break
                    
                # Small delay to prevent high CPU usage
                time.sleep(0.1)
            except curses.error:
                # Terminal resize or other error
                pass
            except Exception:
                # Ignore other errors to keep UI running
                pass
                
    def _draw_ui(self):
        """Draw the UI"""
        if not self.stdscr:
            return
            
        try:
            height, width = self.stdscr.getmaxyx()
            self.stdscr.clear()
            
            # Draw header
            self._draw_header(width)
            
            # Draw progress overview
            self._draw_progress_overview(width)
            
            # Draw task list
            task_area_height = height // 2 - 6
            self._draw_tasks(task_area_height, width)
            
            # Draw log area
            log_start_y = task_area_height + 6
            log_area_height = height - log_start_y - 1
            self._draw_logs(log_start_y, log_area_height, width)
            
            # Draw footer
            self._draw_footer(height - 1, width)
            
            self.stdscr.refresh()
        except curses.error:
            pass
            
    def _draw_header(self, width):
        """Draw the header"""
        title = "AutoTest - Automated Penetration Testing Framework"
        self._draw_centered(0, title, curses.color_pair(4) | curses.A_BOLD)
        self.stdscr.addstr(1, 0, "=" * width, curses.color_pair(5))
        
    def _draw_progress_overview(self, width):
        """Draw progress overview"""
        y = 3
        
        # Overall progress
        elapsed = time.time() - self.start_time if self.start_time else 0
        elapsed_str = str(timedelta(seconds=int(elapsed))).split('.')[0]
        
        progress_pct = (self.completed_targets / self.total_targets * 100) if self.total_targets > 0 else 0
        
        self.stdscr.addstr(y, 2, f"Progress: {self.completed_targets}/{self.total_targets} targets ({progress_pct:.1f}%)", curses.color_pair(5))
        self.stdscr.addstr(y, width - 20, f"Elapsed: {elapsed_str}", curses.color_pair(5))
        
        # Progress bar
        y += 1
        bar_width = width - 4
        filled = int(bar_width * progress_pct / 100)
        bar = "[" + "█" * filled + "░" * (bar_width - filled) + "]"
        self.stdscr.addstr(y, 2, bar, curses.color_pair(1) if progress_pct == 100 else curses.color_pair(5))
        
        # Current target
        if self.current_target:
            y += 2
            self.stdscr.addstr(y, 2, f"Current Target: {self.current_target}", curses.color_pair(2))
            
    def _draw_tasks(self, height, width):
        """Draw task list"""
        y = 7
        self.stdscr.addstr(y, 2, "Tasks:", curses.color_pair(4) | curses.A_BOLD)
        y += 1
        self.stdscr.addstr(y, 0, "-" * width, curses.color_pair(5))
        y += 1
        
        with self.lock:
            tasks = list(self.tasks.values())
            
        # Draw tasks
        max_tasks = height - 2
        for i, task in enumerate(tasks[:max_tasks]):
            self._draw_task(y + i, task, width - 4, indent=2)
            
    def _draw_task(self, y, task: TaskInfo, width, indent=0):
        """Draw a single task"""
        # Status icon
        status_icons = {
            TaskStatus.PENDING: ("⋯", curses.color_pair(5)),
            TaskStatus.RUNNING: ("▶", curses.color_pair(2)),
            TaskStatus.COMPLETED: ("✓", curses.color_pair(1)),
            TaskStatus.FAILED: ("✗", curses.color_pair(3)),
            TaskStatus.SKIPPED: ("⊘", curses.color_pair(5)),
        }
        icon, color = status_icons.get(task.status, ("?", curses.color_pair(5)))
        
        # Task line
        x = indent
        self.stdscr.addstr(y, x, icon, color)
        x += 2
        
        # Task name
        name_width = min(30, width - x - 20)
        task_name = task.name[:name_width].ljust(name_width)
        self.stdscr.addstr(y, x, task_name, color)
        x += name_width + 2
        
        # Progress or status
        if task.status == TaskStatus.RUNNING:
            # Show progress bar
            bar_width = 20
            filled = int(bar_width * task.progress / task.max_progress)
            progress_bar = f"[{'=' * filled}{' ' * (bar_width - filled)}] {task.progress}%"
            self.stdscr.addstr(y, x, progress_bar, color)
        elif task.message:
            # Show message
            msg = task.message[:width - x]
            self.stdscr.addstr(y, x, msg, color)
            
        # Time
        if task.start_time:
            time_str = task.elapsed_time
            self.stdscr.addstr(y, width - 10 + indent, time_str, curses.color_pair(5))
            
    def _draw_logs(self, y, height, width):
        """Draw log area"""
        self.stdscr.addstr(y, 2, "Logs:", curses.color_pair(4) | curses.A_BOLD)
        y += 1
        self.stdscr.addstr(y, 0, "-" * width, curses.color_pair(5))
        y += 1
        
        # Get recent logs
        with self.lock:
            logs = self.log_messages[-(height-2):] if height > 2 else []
            
        # Draw logs
        for i, (timestamp, message) in enumerate(logs):
            if i >= height - 2:
                break
            try:
                # Format timestamp
                ts = datetime.fromtimestamp(float(timestamp)).strftime("%H:%M:%S")
                
                # Truncate message if needed
                max_msg_len = width - 12
                if len(message) > max_msg_len:
                    message = message[:max_msg_len-3] + "..."
                    
                self.stdscr.addstr(y + i, 2, f"{ts} | {message}", curses.color_pair(5))
            except curses.error:
                pass
                
    def _draw_footer(self, y, width):
        """Draw footer"""
        self.stdscr.addstr(y, 0, "-" * width, curses.color_pair(5))
        footer = "Press 'q' to quit"
        self.stdscr.addstr(y, 2, footer, curses.color_pair(5))
        
    def _draw_centered(self, y, text, attr=0):
        """Draw centered text"""
        if not self.stdscr:
            return
        height, width = self.stdscr.getmaxyx()
        x = (width - len(text)) // 2
        try:
            self.stdscr.addstr(y, x, text, attr)
        except curses.error:
            pass
            
    # Task management methods
    def add_task(self, name: str, max_progress: int = 100) -> str:
        """Add a new task"""
        with self.lock:
            task = TaskInfo(name=name, max_progress=max_progress)
            self.tasks[name] = task
        return name
        
    def update_task(self, name: str, status: TaskStatus = None, progress: int = None, 
                   message: str = None, error: str = None):
        """Update task status"""
        with self.lock:
            if name not in self.tasks:
                return
                
            task = self.tasks[name]
            
            if status is not None:
                task.status = status
                if status == TaskStatus.RUNNING and task.start_time is None:
                    task.start_time = time.time()
                elif status in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.SKIPPED]:
                    task.end_time = time.time()
                    
            if progress is not None:
                task.progress = progress
                
            if message is not None:
                task.message = message
                
            if error is not None:
                task.error = error
                
    def complete_task(self, name: str, success: bool = True, message: str = None):
        """Mark task as complete"""
        status = TaskStatus.COMPLETED if success else TaskStatus.FAILED
        self.update_task(name, status=status, progress=100, message=message)
        
    def log(self, message: str):
        """Add a log message"""
        with self.lock:
            timestamp = str(time.time())
            self.log_messages.append((timestamp, message))
            
            # Trim old messages
            if len(self.log_messages) > self.max_log_messages:
                self.log_messages = self.log_messages[-self.max_log_messages:]
                
    def set_progress(self, completed: int, total: int):
        """Set overall progress"""
        self.completed_targets = completed
        self.total_targets = total
        
    def set_current_target(self, target: str):
        """Set current target being processed"""
        self.current_target = target
    
    def run(self):
        """Run the TUI - alias for start() for compatibility"""
        self.start()