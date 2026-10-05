"""Driver transport with caller-owned snapshot release performed by IOCTL, too."""
import os
from driver_bridge import KernelDriverBridge as BaseBridge


class KernelOnlyBridge(BaseBridge):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        from request_scheduler import Scheduler
        self.scheduler=Scheduler(self)

    def read_process_memory_snapshot(self, pid, read_addr, size):
        # The driver allocates the returned copy in the IOCTL caller. Reading that
        # local response uses ctypes, never a target-process handle or Win32 RPM.
        with self._lock:
            result = self.read_process_memory(pid, read_addr, size)
            pointer = int(result.get('dumped_address', '0x0'), 16)
            if result['success'] and pointer:
                freed = self.free_virtual_memory(os.getpid(), pointer)
                if not freed.get('success'):
                    raise RuntimeError('IOCTL snapshot release failed: '+str(freed))
            return result
