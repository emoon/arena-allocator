use core::ffi::c_void;
use std::result::Result;

#[derive(Debug)]
pub enum ArenaError {
    ReserveFailed(String),
    ProtectionFailed(String),
    OutOfReservedMemory,
}

#[cfg(not(target_os = "windows"))]
mod posix {
    use crate::ArenaError;
    use core::ffi::{c_void, CStr};
    use core::ptr::null_mut;
    use libc::{mmap, mprotect, strerror_r, sysconf};
    use libc::{MAP_ANON, MAP_PRIVATE, PROT_NONE, PROT_READ, PROT_WRITE, _SC_PAGESIZE};
    use std::io;

    const MAP_FAILED: *mut c_void = !0 as *mut c_void;

    pub(crate) fn get_page_size() -> usize {
        unsafe { sysconf(_SC_PAGESIZE) as usize }
    }

    fn get_last_error_code() -> i32 {
        io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    fn get_last_error_message() -> String {
        let err_code = get_last_error_code();
        let mut buf = [0i8; 256];
        unsafe {
            strerror_r(err_code, buf.as_mut_ptr(), buf.len());
            let c_str = CStr::from_ptr(buf.as_ptr());
            c_str.to_string_lossy().into_owned()
        }
    }

    pub(crate) fn reserve_range(size: usize) -> Result<*mut c_void, ArenaError> {
        let ptr = unsafe { mmap(null_mut(), size, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0) };
        if ptr == MAP_FAILED {
            return Err(ArenaError::ReserveFailed(get_last_error_message()));
        }
        Ok(ptr)
    }

    pub(crate) fn commit_memory(ptr: *mut c_void, size: usize) -> Result<(), ArenaError> {
        let result = unsafe { mprotect(ptr, size, PROT_READ | PROT_WRITE) };
        if result != 0 {
            return Err(ArenaError::ProtectionFailed(get_last_error_message()));
        }
        Ok(())
    }

    pub(crate) fn decommit_memory(ptr: *mut c_void, size: usize) -> Result<(), ArenaError> {
        let result = unsafe { mprotect(ptr, size, PROT_NONE) };
        if result != 0 {
            return Err(ArenaError::ProtectionFailed(get_last_error_message()));
        }
        Ok(())
    }

    #[cfg(debug_assertions)]
    pub(crate) fn protect_memory(ptr: *mut c_void, size: usize) -> Result<(), ArenaError> {
        let result = unsafe { mprotect(ptr, size, PROT_NONE) };
        if result != 0 {
            return Err(ArenaError::ProtectionFailed(get_last_error_message()));
        }
        Ok(())
    }

    #[cfg(debug_assertions)]
    pub(crate) fn unprotect_memory(ptr: *mut c_void, size: usize) -> Result<(), ArenaError> {
        let result = unsafe { mprotect(ptr, size, PROT_READ | PROT_WRITE) };
        if result != 0 {
            return Err(ArenaError::ProtectionFailed(get_last_error_message()));
        }
        Ok(())
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use crate::ArenaError;
    use core::{ffi::c_void, mem::zeroed};
    use std::{ffi::OsString, os::windows::ffi::OsStringExt, ptr::null_mut};

    const FORMAT_MESSAGE_ALLOCATE_BUFFER: u32 = 0x00000100;
    const FORMAT_MESSAGE_FROM_SYSTEM: u32 = 0x00001000;
    const FORMAT_MESSAGE_IGNORE_INSERTS: u32 = 0x00000200;

    const MEM_COMMIT: u32 = 0x00001000;
    const MEM_DECOMMIT: u32 = 0x00004000;
    const MEM_RELEASE: u32 = 0x8000;
    const MEM_RESERVE: u32 = 0x00002000;
    const PAGE_NOACCESS: u32 = 0x01;
    const PAGE_READWRITE: u32 = 0x04;

    #[repr(C)]
    struct SYSTEM_INFO {
        wProcessorArchitecture: u16,
        wReserved: u16,
        dwPageSize: u32,
        lpMinimumApplicationAddress: *mut u8,
        lpMaximumApplicationAddress: *mut u8,
        dwActiveProcessorMask: *mut u64,
        dwNumberOfProcessors: u32,
        dwProcessorType: u32,
        dwAllocationGranularity: u32,
        wProcessorLevel: u16,
        wProcessorRevision: u16,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetSystemInfo(lpSystemInfo: *mut SYSTEM_INFO);
        fn GetLastError() -> u32;
        fn FormatMessageW(
            dwFlags: u32,
            lpSource: *const u16,
            dwMessageId: u32,
            dwLanguageId: u32,
            lpBuffer: *mut u16,
            nSize: u32,
            Arguments: *mut *mut u8,
        ) -> u32;
        fn LocalFree(hMem: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
        fn VirtualAlloc(
            lpAddress: *mut core::ffi::c_void,
            dwSize: usize,
            flAllocationType: u32,
            flProtect: u32,
        ) -> *mut core::ffi::c_void;
        fn VirtualProtect(
            lpAddress: *mut core::ffi::c_void,
            dwSize: usize,
            flNewProtect: u32,
            lpflOldProtect: *mut u32,
        ) -> i32;
        fn VirtualFree(lpAddress: *mut core::ffi::c_void, dwSize: usize, dwFreeType: u32) -> i32;
    }

    fn get_system_info() -> SYSTEM_INFO {
        let mut info: SYSTEM_INFO = unsafe { zeroed() };
        unsafe {
            GetSystemInfo(&mut info);
        }
        info
    }

    pub(crate) fn get_page_size() -> usize {
        let info = get_system_info();
        info.dwPageSize as usize
    }

    fn get_last_error_message() -> String {
        unsafe {
            let error_code = GetLastError();
            if error_code == 0 {
                return String::new();
            }

            let mut buf: *mut u16 = null_mut();
            let size = FormatMessageW(
                FORMAT_MESSAGE_ALLOCATE_BUFFER
                    | FORMAT_MESSAGE_FROM_SYSTEM
                    | FORMAT_MESSAGE_IGNORE_INSERTS,
                null_mut(),
                error_code,
                0,
                &mut buf as *mut *mut u16 as *mut u16,
                0,
                null_mut(),
            );

            if size == 0 {
                return format!("Unknown error code: {}", error_code);
            }

            let message = OsString::from_wide(core::slice::from_raw_parts(buf, size as usize))
                .to_string_lossy()
                .into_owned();
            LocalFree(buf as *mut _);
            message
        }
    }

    pub(crate) fn reserve_range(size: usize) -> Result<*mut c_void, ArenaError> {
        let ptr = unsafe { VirtualAlloc(null_mut(), size, MEM_RESERVE, PAGE_READWRITE) };
        if ptr.is_null() {
            return Err(ArenaError::ReserveFailed(get_last_error_message()));
        }
        Ok(ptr)
    }

    pub(crate) fn commit_memory(
        ptr: *mut core::ffi::c_void,
        size: usize,
    ) -> Result<(), ArenaError> {
        let success = unsafe { VirtualAlloc(ptr, size, MEM_COMMIT, PAGE_READWRITE) };
        if success.is_null() {
            return Err(ArenaError::ProtectionFailed(get_last_error_message()));
        }
        Ok(())
    }

    pub(crate) fn decommit_memory(
        ptr: *mut core::ffi::c_void,
        size: usize,
    ) -> Result<(), ArenaError> {
        let success = unsafe { VirtualFree(ptr, size, MEM_DECOMMIT) };
        if success == 0 {
            return Err(ArenaError::ProtectionFailed(get_last_error_message()));
        }
        Ok(())
    }

    #[cfg(debug_assertions)]
    pub(crate) fn protect_memory(
        ptr: *mut core::ffi::c_void,
        size: usize,
    ) -> Result<(), ArenaError> {
        let mut old_protect = 0;
        let success =
            unsafe { VirtualProtect(ptr, size, PAGE_NOACCESS, &mut old_protect as *mut u32) };
        if success == 0 {
            return Err(ArenaError::ProtectionFailed(get_last_error_message()));
        }
        Ok(())
    }

    #[cfg(debug_assertions)]
    pub(crate) fn unprotect_memory(
        ptr: *mut core::ffi::c_void,
        size: usize,
    ) -> Result<(), ArenaError> {
        let mut old_protect = 0;
        let success =
            unsafe { VirtualProtect(ptr, size, PAGE_READWRITE, &mut old_protect as *mut u32) };
        if success == 0 {
            return Err(ArenaError::ProtectionFailed(get_last_error_message()));
        }
        Ok(())
    }
}

#[cfg(not(target_os = "windows"))]
pub(crate) use posix::*;

#[cfg(target_os = "windows")]
pub(crate) use windows::*;

#[derive(Copy, Clone)]
struct VmRange<'a> {
    ptr: *mut c_void,
    reserved_size: usize,
    committed_size: usize,
    pos: usize,
    page_size: usize,
    marker: core::marker::PhantomData<&'a c_void>,
}

/// Specifies whether the memory should be protected after it is decommitted.
/// This is useful for debugging purposes, as it can help catch use-after-free bugs.
/// The way this works is that the memory is that all the memory is set as "no access".
/// This means if some code is trying to access the memory it will cause a exception.
///
//enum UseSafteyRange {
//    Yes,
//    No,
//}

impl<'a> VmRange<'a> {
    pub fn new(reserved_size: usize) -> Result<Self, ArenaError> {
        let page_size = get_page_size();
        let ptr = reserve_range(std::cmp::max(reserved_size, page_size))?;
        Ok(Self {
            ptr,
            reserved_size,
            committed_size: 0,
            pos: 0,
            marker: core::marker::PhantomData,
            page_size,
        })
    }

    #[inline]
    fn align_pow2(x: usize, b: usize) -> usize {
        (x + b - 1) & !(b - 1)
    }

    /// Allocates a raw memory block in the arena.
    ///
    /// # Safety
    /// The returned data is uninitialized. The caller must ensure that the data is
    /// properly initialized.
    pub(crate) unsafe fn alloc_raw(
        &mut self,
        size: usize,
        alignment: usize,
    ) -> Result<&'a mut [u8], ArenaError> {
        let new_pos = self.pos + Self::align_pow2(size, alignment);
        let commit_size = Self::align_pow2(size, self.page_size);

        if self.committed_size + commit_size > self.reserved_size {
            return Err(ArenaError::OutOfReservedMemory);
        }

        // If we have already committed the memory, we can just return a slice
        if new_pos < self.committed_size {
            let return_slice = std::slice::from_raw_parts_mut(self.ptr as *mut u8, size);
            self.pos = new_pos;
            return Ok(return_slice);
        }

        commit_memory(self.ptr.add(self.committed_size), commit_size)?;

        self.committed_size += commit_size;
        let return_slice = std::slice::from_raw_parts_mut(self.ptr.add(self.pos) as *mut u8, size);
        self.pos = new_pos;
        Ok(return_slice)
    }

    /// Allocates an array of `T` elements in the arena.
    ///
    /// # Safety
    /// The returned data is uninitialized. The caller must ensure that the data is
    /// properly initialized.
    pub(crate) unsafe fn alloc_array<T: Sized>(
        &mut self,
        count: usize,
    ) -> Result<&'a mut [T], ArenaError> {
        let size = count * core::mem::size_of::<T>();
        let alignment = core::mem::align_of::<T>();
        let slice = self.alloc_raw(size, alignment)?;
        let ptr = slice.as_mut_ptr() as *mut T;
        Ok(unsafe { std::slice::from_raw_parts_mut(ptr, size) })
    }

    /// Allocates an array of `T` elements in the arena and initializes them with the default
    /// value.
    pub(crate) fn alloc_array_init<T: Default + Sized>(
        &mut self,
        count: usize,
    ) -> Result<&'a mut [T], ArenaError> {
        let size = count * core::mem::size_of::<T>();
        let alignment = core::mem::align_of::<T>();
        let slice = unsafe { self.alloc_raw(size, alignment)? };
        let ptr = slice.as_mut_ptr() as *mut T;
        let slice = unsafe { std::slice::from_raw_parts_mut(ptr, count) };

        for v in slice.iter_mut() {
            *v = T::default();
        }

        Ok(slice)
    }

    /// Allocates a single instance of `T` in the arena.
    ///
    /// # Safety
    /// The returned data is uninitialized. The caller must ensure that the data is
    /// properly initialized.
    pub(crate) unsafe fn alloc<T: Sized>(&mut self) -> Result<&'a mut T, ArenaError> {
        let size = core::mem::size_of::<T>();
        let alignment = core::mem::align_of::<T>();
        let slice = self.alloc_raw(size, alignment)?;
        let ptr = slice.as_mut_ptr() as *mut T;
        Ok(unsafe { &mut *ptr })
    }

    pub(crate) fn alloc_init<T: Default + Sized>(&mut self) -> Result<&'a mut T, ArenaError> {
        let size = core::mem::size_of::<T>();
        let alignment = core::mem::align_of::<T>();
        let slice = unsafe { self.alloc_raw(size, alignment)? };
        let ptr = slice.as_mut_ptr() as *mut T;
        unsafe { ptr.write(T::default()) };
        Ok(unsafe { &mut *ptr })
    }

    #[inline]
    pub(crate) fn rewind(&mut self) {
        self.pos = 0;
    }

    #[cfg(debug_assertions)]
    pub(crate) fn protect(&mut self) {
        protect_memory(self.ptr, self.committed_size).unwrap();
    }

    #[cfg(debug_assertions)]
    pub(crate) fn unprotect(&mut self) {
        unprotect_memory(self.ptr, self.committed_size).unwrap();
    }

    #[inline]
    pub(crate) fn decomit(&mut self) -> Result<(), ArenaError> {
        decommit_memory(self.ptr, self.committed_size)?;
        self.committed_size = 0;
        self.pos = 0;
        Ok(())
    }
}

pub struct Arena<'a> {
    current: VmRange<'a>,
    //#[cfg(debug_assertions)]
    prev: VmRange<'a>,
}

impl<'a> Arena<'a> {
    pub fn new(size: usize) -> Result<Self, ArenaError> {
        let current = VmRange::new(size)?;
        #[cfg(debug_assertions)]
        let prev = VmRange::new(size)?;

        Ok(Self {
            current,
            #[cfg(debug_assertions)]
            prev,
        })
    }

    pub unsafe fn alloc_raw(
        &mut self,
        size: usize,
        alignment: usize,
    ) -> Result<&'a mut [u8], ArenaError> {
        self.current.alloc_raw(size, alignment)
    }

    pub unsafe fn alloc_array<T: Sized>(
        &mut self,
        count: usize,
    ) -> Result<&'a mut [T], ArenaError> {
        self.current.alloc_array(count)
    }

    pub unsafe fn alloc<T: Sized>(&mut self) -> Result<&'a mut T, ArenaError> {
        self.current.alloc()
    }

    pub fn alloc_init<T: Default + Sized>(&mut self) -> Result<&'a mut T, ArenaError> {
        self.current.alloc_init()
    }

    pub fn alloc_array_init<T: Default + Sized>(
        &mut self,
        count: usize,
    ) -> Result<&'a mut [T], ArenaError> {
        self.current.alloc_array_init(count)
    }

    #[cfg(debug_assertions)]
    pub fn rewind(&mut self) {
        self.current.protect();

        std::mem::swap(&mut self.current, &mut self.prev);

        // Unprotect the new current range and rewind the position to the start
        self.current.unprotect();
        self.current.rewind();
    }

    #[cfg(not(debug_assertions))]
    pub fn rewind(&mut self) {
        self.current.rewind();
    }
}

impl Drop for Arena<'_> {
    #[cfg(debug_assertions)]
    fn drop(&mut self) {
        self.current.decomit().unwrap();
        self.prev.decomit().unwrap();
    }

    #[cfg(not(debug_assertions))]
    fn drop(&mut self) {
        self.current.decomit().unwrap();
    }
}

pub struct TypedArena<'a, T: Default + Sized> {
    arena: Arena<'a>,
    ptr_type: core::marker::PhantomData<&'a T>,
}

impl<'a, T: Default + Sized> TypedArena<'a, T> {
    pub fn new(size: usize) -> Result<Self, ArenaError> {
        Ok(Self {
            arena: Arena::new(size)?,
            ptr_type: core::marker::PhantomData,
        })
    }

    pub fn alloc(&mut self) -> Result<&'a mut T, ArenaError> {
        self.arena.alloc_init()
    }

    pub fn alloc_array(&mut self, count: usize) -> Result<&'a mut [T], ArenaError> {
        self.arena.alloc_array_init(count)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_arena() {
        let mut arena = Arena::new(16 * 1024).unwrap();
        let slice = unsafe { arena.alloc_raw(1024, 16).unwrap() };
        assert_eq!(slice.len(), 1024);
        assert_eq!(slice.as_ptr() as usize % 16, 0);
        assert!(slice.as_ptr() != std::ptr::null_mut());
    }

    #[test]
    fn test_fail_reserve() {
        let result = Arena::new(usize::MAX);
        assert!(result.is_err());
    }

    #[test]
    fn test_fail_commit() {
        let size = 16 * 1024;
        let mut arena = Arena::new(size).unwrap();
        let result = unsafe { arena.alloc_raw(size * 2, 16) };
        assert!(result.is_err());
    }

    #[test]
    fn test_typed_arena() {
        let mut arena = TypedArena::<u32>::new(32 * 1024).unwrap();
        let single = arena.alloc().unwrap();
        assert_eq!(*single, 0);
        *single = 42;
        assert_eq!(*single, 42);

        let array = arena.alloc_array(1024).unwrap();
        assert_eq!(array.len(), 1024);
        for i in 0..1024 {
            assert_eq!(array[i], 0);
            array[i] = i as u32;
        }
        for i in 0..1024 {
            assert_eq!(array[i], i as u32);
        }
    }
}

/*
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod tests {
    use libc::{fork, waitpid, WIFEXITED, WIFSIGNALED, SIGSEGV};
    use std::process;

    #[test]
    fn test_crash_handling() {
        unsafe {
            let pid = fork();
            if pid == -1 {
                panic!("Failed to fork process");
            } else if pid == 0 {
                // Child process
                // Cause a segmentation fault by dereferencing a null pointer
                let ptr: *mut i32 = std::ptr::null_mut();
                *ptr = 42; // This will cause a crash
            } else {
                // Parent process
                let mut status = 0;
                waitpid(pid, &mut status, 0);
                if WIFSIGNALED(status) && libc::WTERMSIG(status) == SIGSEGV {
                    println!("Child process crashed as expected");
                } else if WIFEXITED(status) {
                    println!("Child process exited normally, but crash was expected");
                    process::exit(1); // Mark test as failed if child didn't crash
                }
            }
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod tests {
    #[test]
    fn test_crash_handling() {
        // No-op or a test that simply passes, if you want to avoid a false failure on other OSes
        println!("This test is only run on Linux and macOS.");
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod tests {
    use libc::{fork, waitpid, WIFEXITED, WIFSIGNALED, SIGSEGV};
    use std::process;

    #[test]
    fn test_crash_handling() {
        unsafe {
            let pid = fork();
            if pid == -1 {
                panic!("Failed to fork process");
            } else if pid == 0 {
                // Child process
                // Cause a segmentation fault by dereferencing a null pointer
                let ptr: *mut i32 = std::ptr::null_mut();
                *ptr = 42; // This will cause a crash
            } else {
                // Parent process
                let mut status = 0;
                waitpid(pid, &mut status, 0);
                if WIFSIGNALED(status) && libc::WTERMSIG(status) == SIGSEGV {
                    println!("Child process crashed as expected");
                } else if WIFEXITED(status) {
                    println!("Child process exited normally, but crash was expected");
                    process::exit(1); // Mark test as failed if child didn't crash
                }
            }
        }
    }
}

#[cfg(target_os = "windows")]
mod tests {
    extern crate winapi;
    use std::ptr::null_mut;
    use std::process;
    use winapi::um::processthreadsapi::{CreateProcessW, TerminateProcess, PROCESS_INFORMATION, STARTUPINFOW};
    use winapi::um::errhandlingapi::RaiseException;
    use winapi::um::winbase::{CREATE_NEW_CONSOLE, INFINITE};
    use winapi::um::synchapi::WaitForSingleObject;
    use winapi::um::winnt::{EXCEPTION_NONCONTINUABLE, EXCEPTION_ACCESS_VIOLATION};

    #[test]
    fn test_crash_handling() {
        unsafe {
            let mut si: STARTUPINFOW = std::mem::zeroed();
            let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
            si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;

            // Convert the command line to a wide string
            let command = std::ffi::OsString::from("child_process");
            let mut command_wide: Vec<u16> = command.encode_wide().collect();
            command_wide.push(0);

            // Create a new child process
            let result = CreateProcessW(
                null_mut(),                     // lpApplicationName
                command_wide.as_mut_ptr(),      // lpCommandLine
                null_mut(),                     // lpProcessAttributes
                null_mut(),                     // lpThreadAttributes
                0,                              // bInheritHandles
                CREATE_NEW_CONSOLE,             // dwCreationFlags
                null_mut(),                     // lpEnvironment
                null_mut(),                     // lpCurrentDirectory
                &mut si,                        // lpStartupInfo
                &mut pi                         // lpProcessInformation
            );

            if result == 0 {
                panic!("Failed to create child process");
            }

            // Simulate a crash in the child process
            if pi.hProcess != null_mut() {
                RaiseException(
                    EXCEPTION_ACCESS_VIOLATION, // Exception code
                    EXCEPTION_NONCONTINUABLE,   // Exception flags
                    0,                          // Number of arguments
                    null_mut(),                 // Arguments
                );
            }

            // Wait for the child process to exit
            WaitForSingleObject(pi.hProcess, INFINITE);

            // Check if the child process crashed as expected
            let mut exit_code: u32 = 0;
            winapi::um::processthreadsapi::GetExitCodeProcess(pi.hProcess, &mut exit_code);
            if exit_code == EXCEPTION_ACCESS_VIOLATION {
                println!("Child process crashed as expected");
            } else {
                println!("Child process exited normally, but crash was expected");
                process::exit(1); // Mark test as failed if child didn't crash
            }

            // Clean up handles
            TerminateProcess(pi.hProcess, 0);
            winapi::um::handleapi::CloseHandle(pi.hProcess);
            winapi::um::handleapi::CloseHandle(pi.hThread);
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod tests {
    #[test]
    fn test_crash_handling() {
        // No-op or a test that simply passes, if you want to avoid a false failure on other OSes
        println!("This test is only run on Linux, macOS, and Windows.");
    }
}
/[dev-dependencies]
winapi = { version = "0.3", features = ["consoleapi", "processthreadsapi", "handleapi", "winbase", "errhandlingapi", "synchapi", "winnt"] }

*/

