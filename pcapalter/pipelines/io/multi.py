import atexit
import inspect
import os
import platform
import multiprocessing
import time
from typing import Callable, Optional, TypeVar
import warnings
import psutil
from ... import utils
logger = utils.logger

def lower_process_priority(pid: Optional[int] = None):
    parent_process = psutil.Process()
    child_process = psutil.Process(pid)
    # Make sure the various subprocesses do not freeze the system
    if platform.system() == "Windows":
        try:
            child_process.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
        except:
            warnings.warn(
                "Failed to lower process I/O priority: Kitsune may consume a lot of resources and freeze the system",
                RuntimeWarning,
            )
    else:
        try:
            child_process.nice(parent_process.nice() + 3)
        except:
            warnings.warn(
                "Failed to lower process I/O priority: Kitsune may consume a lot of resources and freeze the system",
                RuntimeWarning,
            )


def setup_subprocess(
    instance,
    args: tuple,
    kwargs: dict,
    queue_in: multiprocessing.Queue,
    queue_out: multiprocessing.Queue,
    debug: bool = False,
):
    if debug:
        os.environ.update({"DEBUG": "TRUE"})
    if isinstance(instance, type):
        instance = instance(*args, **kwargs)

    while True:
        # Receive new input
        method_name, method_args, method_kwargs = queue_in.get()

        # Shutdown if that was the command
        if method_name == "__shutdown__":
            logger.info("Received shutdown in DedicatedProcessObject subprocess")
            break

        # Process input and return output
        try:
            result = getattr(instance, method_name)(*method_args, **method_kwargs)
        except Exception as e:
            queue_out.put(e)
            return
        queue_out.put(result)
        time.sleep(0.1)

    atexit._run_exitfuncs()


class DedicatedProcessObject:
    T = TypeVar("T")

    def __init__(
        self, instance, *args, process_type, queue_type, debug, lower_priority, **kwargs
    ):
        caller = inspect.stack()[1].function
        if caller != "instantiate":
            warnings.warn(
                "DedicatedProcessObject should be created using DedicatedProcessObject.instantiate() instead of calling DedicatedProcessObject() directly",
                RuntimeWarning,
            )

        self.__debug = debug or os.environ.get("DEBUG") == "TRUE"
        if self.__debug:
            warnings.warn(
                "DedicatedProcessObject is used in DEBUG mode, no new process is spawned."
            )
            if isinstance(instance, type):
                self.__instance = instance(*args, **kwargs)
            else:
                self.__instance = instance
            return

        self.__queue_in: multiprocessing.Queue = queue_type()
        self.__queue_out: multiprocessing.Queue = queue_type()

        self.__process: multiprocessing.Process = process_type(
            target=setup_subprocess,
            args=(
                instance,
                args,
                kwargs,
                self.__queue_in,
                self.__queue_out,
            ),
            kwargs={
                "debug": self.__debug,
            },
        )

        self.__process.start()
        if lower_priority and hasattr(self.__process, "pid"):
            lower_process_priority(self.__process.pid)

        atexit.register(self.terminate)

    def terminate(self):
        logger.info("Terminating DedicatedProcessObject")

        # Terminate
        if hasattr(self.__process, "terminate"):
            self.__process.terminate()

    def shutdown(self, timeout=60):
        logger.info("Shutting DedicatedProcessObject down")

        # Shutdown subprocess
        self.__queue_in.put(("__shutdown__", (), {}))

        # Wait
        logged_wait = False
        waited = 0.
        while not self.__queue_in.empty() or not self.__queue_out.empty():
            if not logged_wait:
                pid = None
                if hasattr(self.__process, "pid"):
                    pid = self.__process.pid
                logger.debug(
                    f"Waiting for the queues process {pid} to be emptied before shutting down."
                )
                logged_wait = True

            time.sleep(0.1)
            waited += 0.1
            if waited == timeout:
                break

        if waited < timeout:
            # Join (wait for process to exit)
            if hasattr(self.__process, "join"):
                self.__process.join()

        self.terminate()

    @staticmethod
    def instantiate(
        instance: Callable[[int], T] | T,
        *args,
        process_type=multiprocessing.Process,
        queue_type=multiprocessing.Queue,
        debug=False,
        lower_priority=False,
        **kwargs,
    ) -> (
        "DedicatedProcessObject" | T
    ):  # Actually returns a DedicatedProcessObject wrapping T but this helps the type checker make sense of it.
        return DedicatedProcessObject(
            instance,
            *args,
            process_type=process_type,
            queue_type=queue_type,
            debug=debug,
            lower_priority=lower_priority,
            **kwargs,
        )

    # Should be called from a seperate thread on the main process
    # e.g. using multiprocessing.pool.ThreadPool
    def __getattr__(self, name):
        def method(*args, **kwargs):
            if self.__debug:
                result = getattr(self.__instance, name)(
                    *args,
                    **kwargs,
                )
                return result

            if not self.__process.is_alive():
                raise RuntimeError(
                    "DedicatedProcessObject no longer is alive and exited"
                )

            self.__queue_in.put((name, args, kwargs))
            result = self.__queue_out.get()

            if isinstance(result, Exception):
                raise result

            return result

        return method

    def __getitem__(self, *args, **kwargs):
        return self.__getattr__("__getitem__")(*args, **kwargs)

    def __getstate__(self, *args, **kwargs):
        return self.__getattr__("__getstate__")(*args, **kwargs)

    def __setstate__(self, *args, **kwargs):
        return self.__getattr__("__setstate__")(*args, **kwargs)
