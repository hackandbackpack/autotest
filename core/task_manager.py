"""
Task management and multi-threading coordination for AutoTest.
"""

import threading
import queue
import time
import concurrent.futures
import logging
from typing import List, Dict, Any, Callable, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from .exceptions import TaskError


class TaskStatus(Enum):
    """Task execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TaskPriority(Enum):
    """Task priority levels."""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Task:
    """
    Represents a single task to be executed.
    """
    id: str
    name: str
    function: Callable
    args: tuple = field(default_factory=tuple)
    kwargs: dict = field(default_factory=dict)
    priority: TaskPriority = TaskPriority.NORMAL
    dependencies: List[str] = field(default_factory=list)
    status: TaskStatus = TaskStatus.PENDING
    result: Any = None
    error: Optional[Exception] = None
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    
    # Plugin-specific attributes
    target: Optional[str] = None
    port: Optional[int] = None
    service: Optional[str] = None
    plugin_name: Optional[str] = None
    params: Optional[Dict[str, Any]] = None
    
    def __lt__(self, other):
        """Compare tasks by priority for queue ordering."""
        return self.priority.value > other.priority.value


class TaskManager:
    """
    Manages task execution with support for dependencies and priorities.
    """
    
    def __init__(self, max_workers: int = 10, max_queue_size: int = 1000,
                 memory_limit_mb: int = 1024, cpu_percent_limit: int = 80):
        """
        Initialize TaskManager with resource limits.
        
        Args:
            max_workers: Maximum number of concurrent workers
            max_queue_size: Maximum number of tasks in queue
            memory_limit_mb: Memory limit in MB (per worker)
            cpu_percent_limit: CPU usage limit percentage
        """
        self.max_workers = max_workers
        self.max_queue_size = max_queue_size
        self.memory_limit_mb = memory_limit_mb
        self.cpu_percent_limit = cpu_percent_limit
        self.tasks: Dict[str, Task] = {}
        self.task_queue = queue.PriorityQueue(maxsize=max_queue_size)
        self.results: Dict[str, Any] = {}
        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        self.executor: Optional[concurrent.futures.ThreadPoolExecutor] = None
        self.futures: Dict[str, concurrent.futures.Future] = {}
        self.stats: Dict[str, Any] = {}
        self.completed_tasks: List[Task] = []
        self.failed_tasks: List[Task] = []
        self.running = False
        self._resource_monitor_thread = None
        self._monitor_stop_event = threading.Event()
    
    def add_task(self, task: Task) -> None:
        """
        Add a task to the manager.
        
        Args:
            task: Task to add
            
        Raises:
            TaskError: If task ID already exists
        """
        with self.lock:
            if task.id in self.tasks:
                raise TaskError(f"Task with ID '{task.id}' already exists")
            
            # Check queue size limit
            if len(self.tasks) >= self.max_queue_size:
                raise TaskError(f"Task queue full (limit: {self.max_queue_size})")
            
            self.tasks[task.id] = task
    
    def add_simple_task(self, task_id: str, name: str, function: Callable,
                       *args, priority: TaskPriority = TaskPriority.NORMAL,
                       dependencies: Optional[List[str]] = None, **kwargs) -> None:
        """
        Add a task with simplified parameters.
        
        Args:
            task_id: Unique task identifier
            name: Task name
            function: Function to execute
            *args: Positional arguments for function
            priority: Task priority
            dependencies: List of task IDs this task depends on
            **kwargs: Keyword arguments for function
        """
        task = Task(
            id=task_id,
            name=name,
            function=function,
            args=args,
            kwargs=kwargs,
            priority=priority,
            dependencies=dependencies or []
        )
        self.add_task(task)
    
    def start(self) -> None:
        """Start the task manager."""
        if self.executor is not None:
            raise TaskError("TaskManager is already running")
        
        self.stop_event.clear()
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers)
        self.running = True
        
        # Start resource monitor thread
        self._monitor_stop_event.clear()
        self._resource_monitor_thread = threading.Thread(
            target=self._monitor_resources,
            daemon=True
        )
        self._resource_monitor_thread.start()
        
        # Initialize stats
        import time
        self.stats['start_time'] = time.time()
        
        # Start the scheduler thread
        scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        scheduler_thread.start()
    
    def stop(self, wait: bool = True) -> None:
        """
        Stop the task manager.
        
        Args:
            wait: Whether to wait for running tasks to complete
        """
        self.stop_event.set()
        self._monitor_stop_event.set()
        if self._resource_monitor_thread:
            self._resource_monitor_thread.join(timeout=2)
        self.running = False
        
        # Update end time in stats
        import time
        self.stats['end_time'] = time.time()
        
        if self.executor:
            if wait:
                # Cancel pending futures
                with self.lock:
                    for future in self.futures.values():
                        future.cancel()
                
                self.executor.shutdown(wait=True)
            else:
                self.executor.shutdown(wait=False)
            
            self.executor = None
    
    def wait_for_completion(self, timeout: Optional[float] = None) -> bool:
        """
        Wait for all tasks to complete.
        
        Args:
            timeout: Maximum time to wait (None for no timeout)
            
        Returns:
            True if all tasks completed, False if timeout occurred
        """
        start_time = time.time()
        
        while True:
            with self.lock:
                # Check if all tasks are done
                all_done = all(
                    task.status in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED]
                    for task in self.tasks.values()
                )
                
                if all_done:
                    return True
            
            # Check timeout
            if timeout and (time.time() - start_time) > timeout:
                return False
            
            time.sleep(0.1)
    
    def get_task_status(self, task_id: str) -> TaskStatus:
        """
        Get the status of a task.
        
        Args:
            task_id: Task identifier
            
        Returns:
            Task status
            
        Raises:
            TaskError: If task not found
        """
        with self.lock:
            if task_id not in self.tasks:
                raise TaskError(f"Task '{task_id}' not found")
            return self.tasks[task_id].status
    
    def get_task_result(self, task_id: str) -> Any:
        """
        Get the result of a completed task.
        
        Args:
            task_id: Task identifier
            
        Returns:
            Task result
            
        Raises:
            TaskError: If task not found or not completed
        """
        with self.lock:
            if task_id not in self.tasks:
                raise TaskError(f"Task '{task_id}' not found")
            
            task = self.tasks[task_id]
            if task.status != TaskStatus.COMPLETED:
                raise TaskError(f"Task '{task_id}' is not completed (status: {task.status})")
            
            if task.error:
                raise task.error
            
            return task.result
    
    def get_all_results(self) -> Dict[str, Any]:
        """
        Get results of all completed tasks.
        
        Returns:
            Dictionary mapping task IDs to results
        """
        with self.lock:
            results = {}
            for task_id, task in self.tasks.items():
                if task.status == TaskStatus.COMPLETED and not task.error:
                    results[task_id] = task.result
            return results
    
    def get_failed_tasks(self) -> List[Tuple[str, Exception]]:
        """
        Get all failed tasks with their errors.
        
        Returns:
            List of (task_id, error) tuples
        """
        with self.lock:
            failed = []
            for task_id, task in self.tasks.items():
                if task.status == TaskStatus.FAILED and task.error:
                    failed.append((task_id, task.error))
            return failed
    
    def cancel_task(self, task_id: str) -> bool:
        """
        Cancel a pending or running task.
        
        Args:
            task_id: Task identifier
            
        Returns:
            True if task was cancelled, False otherwise
        """
        with self.lock:
            if task_id not in self.tasks:
                return False
            
            task = self.tasks[task_id]
            
            # Can only cancel pending or running tasks
            if task.status not in [TaskStatus.PENDING, TaskStatus.RUNNING]:
                return False
            
            # Cancel the future if it exists
            if task_id in self.futures:
                future = self.futures[task_id]
                if future.cancel():
                    task.status = TaskStatus.CANCELLED
                    return True
            
            # If task is still pending, mark as cancelled
            if task.status == TaskStatus.PENDING:
                task.status = TaskStatus.CANCELLED
                return True
            
            return False
    
    def get_progress(self) -> Dict[str, int]:
        """
        Get task execution progress.
        
        Returns:
            Dictionary with task counts by status
        """
        with self.lock:
            progress = {
                'total': len(self.tasks),
                'pending': 0,
                'running': 0,
                'completed': 0,
                'failed': 0,
                'cancelled': 0
            }
            
            for task in self.tasks.values():
                progress[task.status.value] += 1
            
            return progress
    
    def _scheduler_loop(self) -> None:
        """Main scheduler loop that manages task execution."""
        while not self.stop_event.is_set():
            self._schedule_ready_tasks()
            time.sleep(0.1)
    
    def _schedule_ready_tasks(self) -> None:
        """Schedule tasks that are ready to run."""
        with self.lock:
            for task in self.tasks.values():
                if task.status != TaskStatus.PENDING:
                    continue
                
                # Check if dependencies are satisfied
                if self._are_dependencies_met(task):
                    # Submit task for execution
                    task.status = TaskStatus.RUNNING
                    task.start_time = time.time()
                    
                    future = self.executor.submit(self._execute_task, task)
                    self.futures[task.id] = future
                    
                    # Add callback to handle completion
                    future.add_done_callback(
                        lambda f, t=task: self._task_completed(t, f)
                    )
    
    def _are_dependencies_met(self, task: Task) -> bool:
        """
        Check if all dependencies of a task are satisfied.
        
        Args:
            task: Task to check
            
        Returns:
            True if all dependencies are met
        """
        for dep_id in task.dependencies:
            if dep_id not in self.tasks:
                # Dependency doesn't exist - this is an error
                task.status = TaskStatus.FAILED
                task.error = TaskError(f"Dependency '{dep_id}' not found")
                return False
            
            dep_task = self.tasks[dep_id]
            if dep_task.status != TaskStatus.COMPLETED:
                return False
            
            if dep_task.error:
                # Dependency failed - this task should fail too
                task.status = TaskStatus.FAILED
                task.error = TaskError(f"Dependency '{dep_id}' failed")
                return False
        
        return True
    
    def _execute_task(self, task: Task) -> Any:
        """
        Execute a single task.
        
        Args:
            task: Task to execute
            
        Returns:
            Task result
        """
        try:
            result = task.function(*task.args, **task.kwargs)
            return result
        except Exception as e:
            raise TaskError(f"Task '{task.id}' failed: {str(e)}") from e
    
    def _task_completed(self, task: Task, future: concurrent.futures.Future) -> None:
        """
        Handle task completion.
        
        Args:
            task: Completed task
            future: Task future
        """
        with self.lock:
            task.end_time = time.time()
            
            try:
                if future.cancelled():
                    task.status = TaskStatus.CANCELLED
                else:
                    task.result = future.result()
                    task.status = TaskStatus.COMPLETED
                    self.results[task.id] = task.result
                    self.completed_tasks.append(task)
            except Exception as e:
                task.status = TaskStatus.FAILED
                task.error = e
                self.failed_tasks.append(task)
            
            # Remove from futures
            self.futures.pop(task.id, None)
    
    def create_task_graph(self) -> Dict[str, List[str]]:
        """
        Create a dependency graph of tasks.
        
        Returns:
            Dictionary mapping task IDs to their dependents
        """
        graph = {task_id: [] for task_id in self.tasks}
        
        for task_id, task in self.tasks.items():
            for dep_id in task.dependencies:
                if dep_id in graph:
                    graph[dep_id].append(task_id)
        
        return graph
    
    def get_execution_order(self) -> List[str]:
        """
        Get the execution order based on dependencies.
        
        Returns:
            List of task IDs in execution order
            
        Raises:
            TaskError: If circular dependencies are detected
        """
        # Topological sort
        visited = set()
        stack = []
        temp_visited = set()
        
        def visit(task_id: str):
            if task_id in temp_visited:
                raise TaskError("Circular dependency detected")
            if task_id in visited:
                return
            
            temp_visited.add(task_id)
            task = self.tasks.get(task_id)
            if task:
                for dep_id in task.dependencies:
                    visit(dep_id)
            
            temp_visited.remove(task_id)
            visited.add(task_id)
            stack.append(task_id)
        
        for task_id in self.tasks:
            if task_id not in visited:
                visit(task_id)
        
        return stack
    
    def create_tasks_from_discovery(self, discovered_hosts: Dict[str, Any], plugins: List[Any], 
                                   port_filter: Optional[str] = None) -> None:
        """
        Create tasks based on discovery results and available plugins.
        
        Args:
            discovered_hosts: Dictionary of discovered hosts with their open ports
            plugins: List of available plugins
            port_filter: Optional port specification to limit plugin execution
        """
        import uuid
        
        # Parse port filter if provided
        allowed_ports = None
        if port_filter:
            allowed_ports = self._parse_port_filter(port_filter)
            logging.info(f"Limiting plugin execution to ports: {sorted(allowed_ports)}")
        
        # Create tasks for each host/port/service combination
        for host, host_info in discovered_hosts.items():
            if isinstance(host_info, dict) and 'ports' in host_info:
                for port in host_info['ports']:
                    # Skip ports not in the filter if specified
                    if allowed_ports and port not in allowed_ports:
                        logging.debug(f"Skipping port {port} - not in allowed ports filter")
                        continue
                    
                    service = host_info.get('services', {}).get(str(port), 'unknown')
                    logging.debug(f"Host {host}, Port {port}, Service: {service}")
                    
                    # Find matching plugins for this service
                    for plugin in plugins:
                        if hasattr(plugin, 'can_handle'):
                            can_handle = plugin.can_handle(service, port)
                            logging.debug(f"Plugin {plugin.name} can_handle({service}, {port}) = {can_handle}")
                            if can_handle:
                                # Create a task for this plugin
                                task_id = str(uuid.uuid4())
                                
                                # Create a closure that captures the plugin and parameters
                                def make_plugin_executor(plugin_instance, target_host, target_port):
                                    def execute_plugin():
                                        # Check if plugin tools are available (unless skipped)
                                        if not getattr(plugin_instance, 'skip_tool_check', False):
                                            tools_available, tool_status = plugin_instance.check_required_tools()
                                            if not tools_available:
                                                missing_tools = plugin_instance.get_missing_tools()
                                                error_msg = "Missing required tools:\n"
                                                for tool in missing_tools:
                                                    error_msg += f"  - {tool['name']}: {tool['install_command']}\n"
                                                raise Exception(error_msg)
                                        
                                        # Check if autotest_instance is available for output_dir
                                        if hasattr(self, 'autotest_instance') and self.autotest_instance:
                                            output_dir = self.autotest_instance.output_manager.session_dir
                                        else:
                                            output_dir = "output"
                                        
                                        # Log task execution
                                        logging.info(f"Executing {plugin_instance.name} plugin for {target_host}:{target_port}")
                                        
                                        # Execute the plugin
                                        try:
                                            result = plugin_instance.execute(
                                                target_host, 
                                                port=target_port,
                                                output_dir=output_dir
                                            )
                                            logging.debug(f"Plugin {plugin_instance.name} returned: {result}")
                                            return result
                                        except Exception as e:
                                            logging.error(f"Plugin {plugin_instance.name} failed: {e}")
                                            raise
                                    return execute_plugin
                            
                                task = Task(
                                    id=task_id,
                                    name=f"{plugin.name}_{host}:{port}",
                                    function=make_plugin_executor(plugin, host, port),
                                    priority=TaskPriority.NORMAL,
                                    target=host,
                                    port=port,
                                    service=service,
                                    plugin_name=plugin.name
                                )
                                
                                self.add_task(task)
    
    def _monitor_resources(self) -> None:
        """
        Monitor system resources and throttle if limits exceeded.
        """
        try:
            import psutil
        except ImportError:
            logging.warning("psutil not installed, resource monitoring disabled")
            return
        
        while not self._monitor_stop_event.is_set():
            try:
                # Check CPU usage
                cpu_percent = psutil.cpu_percent(interval=1)
                
                # Check memory usage
                memory = psutil.virtual_memory()
                memory_used_mb = (memory.total - memory.available) / (1024 * 1024)
                
                # If resources exceed limits, pause task execution
                if cpu_percent > self.cpu_percent_limit:
                    logging.warning(f"CPU usage high ({cpu_percent}%), throttling tasks")
                    time.sleep(2)  # Brief pause to let CPU cool down
                
                # Check per-process memory if possible
                try:
                    process = psutil.Process()
                    process_memory_mb = process.memory_info().rss / (1024 * 1024)
                    if process_memory_mb > self.memory_limit_mb * self.max_workers:
                        logging.warning(f"Memory usage high ({process_memory_mb}MB), throttling tasks")
                        time.sleep(1)
                except:
                    pass
                
                # Brief sleep before next check
                time.sleep(5)
                
            except Exception as e:
                logging.debug(f"Resource monitoring error: {e}")
                time.sleep(10)
    
    def _parse_port_filter(self, port_spec: str) -> Set[int]:
        """Parse port specification into a set of port numbers.
        
        Args:
            port_spec: Port specification (e.g., "22,80,443" or "1-1000")
        
        Returns:
            Set of allowed port numbers
        """
        from typing import Set
        ports = set()
        
        # Parse comma-separated ports and ranges
        for part in port_spec.split(','):
            part = part.strip()
            if '-' in part:
                # Handle range
                try:
                    start, end = part.split('-', 1)
                    start_port = int(start.strip())
                    end_port = int(end.strip())
                    
                    # Validate range
                    if start_port < 1 or end_port > 65535 or start_port > end_port:
                        logging.warning(f"Invalid port range: {part}")
                        continue
                    
                    ports.update(range(start_port, end_port + 1))
                except ValueError:
                    logging.warning(f"Invalid port range format: {part}")
            else:
                # Single port
                try:
                    port = int(part)
                    if 1 <= port <= 65535:
                        ports.add(port)
                    else:
                        logging.warning(f"Invalid port number: {port}")
                except ValueError:
                    logging.warning(f"Invalid port format: {part}")
        
        return ports