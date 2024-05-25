use log::{error, info, trace};
use std::{ffi::c_void, marker::PhantomData, path::Path, sync::Arc};
use sysinfo::{Pid, PidExt};
use thiserror::Error;
use windows_sys::{
    core::PCSTR,
    s,
    Win32::{
        Foundation::{CloseHandle, FALSE, HANDLE, HMODULE},
        System::{
            Diagnostics::Debug::WriteProcessMemory,
            LibraryLoader::{GetModuleHandleA, GetProcAddress},
            Memory::{VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_DECOMMIT, PAGE_READWRITE},
            Threading::{
                CreateRemoteThread, GetExitCodeThread, OpenProcess, WaitForSingleObject, INFINITE,
                PROCESS_CREATE_THREAD, PROCESS_VM_OPERATION, PROCESS_VM_WRITE,
            },
        },
    },
};

type LoadLibraryA = unsafe extern "system" fn(lplibfilename: PCSTR) -> HMODULE;

#[derive(Error, Debug)]
pub enum InjectorError {
    #[error("Payload does not exist: `{0}`")]
    PayloadMissing(String),
    #[error("Payload location unable to be initialized as a CString: `{0}`")]
    PayloadCString(#[from] std::ffi::NulError),
    #[error("Payload location unable to be canonicalized: `{0}`")]
    PayloadCanonicalization(#[from] std::io::Error),
    #[error("Process is not active: `{0}`")]
    ProcessNotActive(String),
    #[error("Unable to obtain handle to Kernel32 Module")]
    KernelModule,
    #[error("Unable to obtain handle to LoadLibrary Proc")]
    LoadLibraryProc,
    #[error("Unable to open process")]
    ProcessOpen,
    #[error("Unable to allocate memory in target process")]
    AllocationFailure,
    #[error("Unable to write specified memory")]
    WriteFailure,
    #[error("Unable to spawn remote thread")]
    RemoteThread,
}

/// Injects the payload pointed to by `payload_location` into `pid`.
pub fn inject_into(
    payload_location: impl AsRef<Path>,
    pid: impl Into<Pid>,
) -> Result<(), InjectorError> {
    let payload_location = match std::fs::canonicalize(payload_location) {
        Ok(p) => p.to_str().unwrap().replace("\\\\?\\", ""),
        Err(e) => return Err(InjectorError::PayloadCanonicalization(e)),
    };
    let pid = pid.into();

    info!(
        "injecting Payload: {:#?} into Pid: {}",
        payload_location, pid
    );

    let kernel_module = get_kernel_module()?;
    info!("locally identified kernel module: {:#?}", kernel_module);

    let load_library_proc = resolve_load_library(kernel_module)?;
    info!(
        "locally identified load library proc: {:#?}",
        load_library_proc as *const usize
    );

    let raw_process = RemoteProcess::open(pid)?;
    let write_size = payload_location.len() + 1;
    let raw_allocation = raw_process.allocate(write_size, MEM_COMMIT, PAGE_READWRITE)?;

    let payload_cstring = match std::ffi::CString::new(payload_location) {
        Ok(cstring) => cstring,
        Err(err) => {
            error!("unable to create CString from payload absolute path");
            return Err(InjectorError::PayloadCString(err));
        }
    };
    raw_allocation.write(payload_cstring.as_ptr() as *mut c_void)?;
    raw_allocation
        .spawn_thread_with_args(load_library_proc)?
        .wait()?;

    Ok(())
}

/// A remote thread which depends on a process.
/// If you want to spawn the thread and then block for its remote completion, consider the wait function.
/// Regardless of how you use the instance, your thread handle will be closed on drop.
/// This does not exit the thread, but it will drop our view of it. And you will not be able to reobtain the handle.
pub struct RemoteThread<'process> {
    _process: RemoteProcess<'process>,
    thread: HANDLE,
}

impl<'process> RemoteThread<'process> {
    /// Provides a function to spawn a remote thread
    pub fn spawn_with_args(
        process: RemoteProcess<'process>,
        allocation: &'process RemoteAllocation,
        entry_function: LoadLibraryA,
    ) -> Result<Self, InjectorError> {
        let thread = unsafe {
            CreateRemoteThread(
                process.inner(),
                std::ptr::null_mut(),
                0,
                // Transmute from 'fn (*const u8) -> isize' to 'fn(*mut c_void) -> u32'.
                Some(std::mem::transmute(entry_function)),
                allocation.inner(),
                0,
                std::ptr::null_mut(),
            )
        };

        if thread == 0 {
            return Err(InjectorError::RemoteThread);
        }

        Ok(RemoteThread {
            _process: process,
            thread,
        })
    }

    /// Consumes the remote thread, waiting for it to exit.
    /// Returns the exit code on success.
    /// Regardless of execution. Self will be consumed and the thread handle closed.
    pub fn wait(self) -> Result<u32, InjectorError> {
        let wait_status = unsafe { WaitForSingleObject(self.thread, INFINITE) };

        if wait_status != 0 {
            return Err(InjectorError::RemoteThread);
        }

        let mut result = 0;
        let _exit_status = unsafe { GetExitCodeThread(self.thread, &mut result) };
        Ok(result)
    }
}

impl<'process> Drop for RemoteThread<'process> {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.thread);
        };
    }
}

/// An allocation of memory in the remote process
pub struct RemoteAllocation<'process> {
    process: RemoteProcess<'process>,
    allocation: *mut c_void,
    size: usize,
}

impl<'process> RemoteAllocation<'process> {
    /// A way to create a remote allocation, given a process we attempt to provision the allocation of a desired size, allocation flags, and protection flags.
    pub fn allocate(
        process: RemoteProcess<'process>,
        size: usize,
        allocation_flags: u32,
        protection_flags: u32,
    ) -> Result<Self, InjectorError> {
        let allocation = unsafe {
            VirtualAllocEx(
                process.inner(),
                std::ptr::null_mut(),
                size,
                allocation_flags,
                protection_flags,
            )
        };

        if allocation.is_null() {
            return Err(InjectorError::AllocationFailure);
        }

        trace!(
            "allocated n bytes: {}, with allocation_flags: {}, and protection_flags: {}",
            size,
            allocation_flags,
            protection_flags
        );

        Ok(RemoteAllocation {
            process,
            allocation,
            size,
        })
    }

    /// Spawns a thread using this remote allocation's address as the input
    /// You should have your arguments aligned properly at the head of this allocation prior to spawning a thread with this as the inputs.
    pub fn spawn_thread_with_args(
        &self,
        entry_function: LoadLibraryA,
    ) -> Result<RemoteThread, InjectorError> {
        RemoteThread::spawn_with_args(self.process.clone(), self, entry_function)
    }

    fn inner(&self) -> *mut c_void {
        self.allocation
    }

    /// Make this public when safer.
    /// Probably force provide the full buffer and desired size on initialize
    fn write(&self, buffer: *mut c_void) -> Result<usize, InjectorError> {
        let mut bytes_written: usize = 0;

        let write_result = unsafe {
            WriteProcessMemory(
                self.process.inner(),
                self.allocation,
                buffer,
                self.size,
                &mut bytes_written,
            )
        };

        if write_result == 0 || bytes_written == 0 {
            return Err(InjectorError::WriteFailure);
        }

        trace!(
            "wrote n bytes: {} for allocation of size: {}",
            bytes_written,
            self.size
        );

        Ok(bytes_written)
    }
}

impl<'process> Drop for RemoteAllocation<'process> {
    fn drop(&mut self) {
        unsafe {
            VirtualFreeEx(
                self.process.inner(),
                self.allocation,
                self.size,
                MEM_DECOMMIT,
            );
        }
    }
}

/// A Process handle. You can initialize with open(pid)
#[derive(Clone)]
pub struct RemoteProcess<'h> {
    handle: Arc<HANDLE>,
    handle_lifetime: PhantomData<&'h ()>,
}

impl<'h> RemoteProcess<'h> {
    /// Attempts to open a handle by pid.
    pub fn open(pid: Pid) -> Result<Self, InjectorError> {
        let handle = unsafe {
            OpenProcess(
                PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
                FALSE,
                pid.as_u32(),
            )
        };

        if handle == 0 {
            return Err(InjectorError::ProcessOpen);
        }

        Ok(Self {
            handle: Arc::new(handle),
            handle_lifetime: PhantomData,
        })
    }

    /// Allocates memory in the raw process.
    pub fn allocate(
        &self,
        size: usize,
        allocation_flags: u32,
        protection_flags: u32,
    ) -> Result<RemoteAllocation, InjectorError> {
        RemoteAllocation::allocate(self.clone(), size, allocation_flags, protection_flags)
    }

    /// A reference to the inner handle
    fn inner(&self) -> HANDLE {
        *self.handle
    }
}

impl Drop for RemoteProcess<'_> {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(*self.handle as HANDLE);
        }
    }
}

/// Attempts to acquire a handle to kernel32.
/// A handle to the kernel32 is required for injection.
pub fn get_kernel_module() -> Result<HMODULE, InjectorError> {
    let kernel_module = unsafe { GetModuleHandleA(s!("kernel32.dll")) };

    if kernel_module == 0 {
        return Err(InjectorError::KernelModule);
    }

    Ok(kernel_module)
}

/// Attempts to resolve LoadLibraryA function locally.
pub fn resolve_load_library(kernel_module: HMODULE) -> Result<LoadLibraryA, InjectorError> {
    let load_library_proc = unsafe { GetProcAddress(kernel_module, s!("LoadLibraryA")) }
        .ok_or(InjectorError::LoadLibraryProc)?;

    let load_library_proc: LoadLibraryA = unsafe { std::mem::transmute(load_library_proc) };

    Ok(load_library_proc)
}
