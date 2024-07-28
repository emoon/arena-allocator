use std::result::Result;
use core::ffi::c_void;
    
#[derive(Debug)]
pub enum ArenaError {
    ReserveFailed(String),
    ProtectionFailed(String),
    OutOfReservedMemory,
}

#[cfg(not(target_os = "windows"))]
mod posix {
    use core::ptr::null_mut;
    use core::ffi::c_void;
    use crate::ArenaError;

    // POSIX Constants
    const _SC_PAGESIZE: i32 = 30;
    const _SC_LARGE_PAGESIZE: i32 = 45;
    const PROT_NONE: i32 = 0x0;
    const PROT_READ: i32 = 0x1;
    const PROT_WRITE: i32 = 0x2;
    const MAP_PRIVATE: i32 = 0x02;
    const MAP_ANON: i32 = 0x20;
    const MAP_FAILED: *mut core::ffi::c_void = !0 as *mut core::ffi::c_void;

    extern "C" {
        fn mmap(
            addr: *mut core::ffi::c_void,
            length: usize,
            prot: i32,
            flags: i32,
            fd: i32,
            offset: isize,
        ) -> *mut core::ffi::c_void;
        fn mprotect(addr: *mut core::ffi::c_void, len: usize, prot: i32) -> i32;
        fn strerror_r(errnum: i32, buf: *mut i8, buflen: usize) -> i32;
        fn __errno_location() -> *mut i32;
        fn sysconf(name: i32) -> i64;
        fn munmap(addr: *mut core::ffi::c_void, length: usize) -> i32;
    }

    pub(crate) fn get_page_size() -> usize {
        unsafe { sysconf(_SC_PAGESIZE) as usize }
    }

    fn get_last_error_code() -> i32 {
        unsafe { *__errno_location() }
    }

    fn get_last_error_message() -> String {
        let err_code = get_last_error_code();
        let mut buf = [0i8; 256];
        unsafe {
            strerror_r(err_code, buf.as_mut_ptr(), buf.len());
            let c_str = core::ffi::CStr::from_ptr(buf.as_ptr());
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

    pub(crate) fn commit_memory(ptr: *mut core::ffi::c_void, size: usize) -> Result<(), ArenaError> {
        let result = unsafe { mprotect(ptr, size, PROT_READ | PROT_WRITE) };
        if result != 0 {
            return Err(ArenaError::ProtectionFailed(get_last_error_message()));
        }
        Ok(())
    }

    pub(crate) fn decommit_memory(ptr: *mut core::ffi::c_void, size: usize) -> Result<(), ArenaError> {
        let result = unsafe { mprotect(ptr, size, PROT_NONE) };
        if result != 0 {
            return Err(ArenaError::ProtectionFailed(get_last_error_message()));
        }
        Ok(())
    }

    pub(crate) fn release_memory(ptr: *mut core::ffi::c_void, size: usize) -> Result<(), ArenaError> {
        let result = unsafe { munmap(ptr, size) };
        if result != 0 {
            return Err(ArenaError::ProtectionFailed(get_last_error_message()));
        }
        Ok(())
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use std::{ffi::OsString, os::windows::ffi::OsStringExt, ptr::null_mut};
    use core::{ffi::c_void, mem::zeroed};
    use crate::ArenaError;

    const FORMAT_MESSAGE_ALLOCATE_BUFFER: u32 = 0x00000100;
    const FORMAT_MESSAGE_FROM_SYSTEM: u32 = 0x00001000;
    const FORMAT_MESSAGE_IGNORE_INSERTS: u32 = 0x00000200;

    const MEM_RESERVE: u32 = 0x00002000;
    const MEM_COMMIT: u32 = 0x00001000;
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
        fn VirtualAlloc(lpAddress: *mut core::ffi::c_void, dwSize: usize, flAllocationType: u32, flProtect: u32) -> *mut core::ffi::c_void;
        fn VirtualProtect(lpAddress: *mut core::ffi::c_void, dwSize: usize, flNewProtect: u32, lpflOldProtect: *mut u32) -> i32;
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
                FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
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

            let message = OsString::from_wide(core::slice::from_raw_parts(buf, size as usize)).to_string_lossy().into_owned();
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

    pub(crate) fn commit_memory(ptr: *mut core::ffi::c_void, size: usize) -> Result<(), ArenaError> {
        let mut old_protect: u32 = 0;
        let success = unsafe { VirtualProtect(ptr, size, PAGE_READWRITE, &mut old_protect) };
        if success == 0 {
            return Err(ArenaError::ProtectionFailed(get_last_error_message()));
        }
        Ok(())
    }

    pub(crate) fn decommit_memory(ptr: *mut core::ffi::c_void, size: usize) -> Result<(), ArenaError> {
        let mut old_protect: u32 = 0;
        let success = unsafe { VirtualProtect(ptr, size, PAGE_NOACCESS, &mut old_protect) };
        if success == 0 {
            return Err(ArenaError::ProtectionFailed(get_last_error_message()));
        }
        Ok(())
    }

    pub(crate) fn release_memory(ptr: *mut core::ffi::c_void, size: usize) -> Result<(), ArenaError> {
        let success = unsafe { VirtualFree(ptr, 0, MEM_RELEASE) };
        if success == 0 {
            return Err(ArenaError::ProtectionFailed(get_last_error_message()));
        }
        Ok(())
    }
}

#[cfg(not(target_os = "windows"))]
pub(crate) use posix::*;

#[cfg(target_os = "windows")]
pub use windows::*;

pub struct Arena<'a> {
    ptr: *mut c_void,
    reserved_size: usize,
    committed_size: usize,
    pos: usize,
    page_size: usize,
    marker: core::marker::PhantomData<&'a c_void>,
}

impl<'a> Arena<'a> {
    pub fn new(size: usize) -> Result<Self, ArenaError> {
        let ptr = reserve_range(size)?;
        Ok(Self {
            ptr,
            reserved_size: size,
            committed_size: 0,
            pos: 0,
            marker: core::marker::PhantomData,
            page_size: get_page_size(),
        })
    }

    #[inline]
    fn align_pow2(x: usize, b: usize) -> usize {
        (x + b - 1) & !(b - 1)
    }

    pub fn alloc(&mut self, size: usize, alignment: usize) -> Result<&'a mut [u8], ArenaError> {
        let new_pos = self.pos + Self::align_pow2(size, alignment);
        let commit_size = Self::align_pow2(size, self.page_size);

        if self.committed_size + commit_size > self.reserved_size {
            return Err(ArenaError::OutOfReservedMemory);
        }
        
        // If we have already committed the memory, we can just return a slice
        if new_pos < self.committed_size {
            let return_slice = unsafe { std::slice::from_raw_parts_mut(self.ptr as *mut u8, size) };
            self.pos = new_pos;
            return Ok(return_slice);
        }

        unsafe { commit_memory(self.ptr.add(self.committed_size), commit_size)? };

        self.committed_size += commit_size;
        let return_slice = unsafe { std::slice::from_raw_parts_mut(self.ptr.add(self.pos) as *mut u8, size) };
        self.pos = new_pos;
        Ok(return_slice)
    }
}

impl Drop for Arena<'_> {
    fn drop(&mut self) {
        decommit_memory(self.ptr, self.committed_size).unwrap();
        release_memory(self.ptr, self.reserved_size).unwrap();
    }
}

pub struct TypedArena<'a, T: Default + Sized> {
    arena: Arena<'a>,
    ptr_type: core::marker::PhantomData<&'a T>,
}

impl <'a, T: Default + Sized> TypedArena<'a, T> {
    pub fn new(size: usize) -> Result<Self, ArenaError> {
        Ok(Self {
            arena: Arena::new(size)?,
            ptr_type: core::marker::PhantomData,
        })
    }

    pub fn alloc(&mut self) -> Result<&'a mut T, ArenaError> {
        let slice = self.arena.alloc(core::mem::size_of::<T>(), core::mem::align_of::<T>())?;
        let ptr = slice.as_mut_ptr() as *mut T;
        unsafe { ptr.write(T::default()) };
        Ok(unsafe { &mut *ptr })
    }

    pub fn alloc_array(&mut self, size: usize) -> Result<&'a mut [T], ArenaError> {
        let mem = self.arena.alloc(core::mem::size_of::<T>() * size, core::mem::align_of::<T>())?;
        let ptr = mem.as_mut_ptr() as *mut T;
        let slice = unsafe { std::slice::from_raw_parts_mut(ptr, size) };

        for v in slice.iter_mut() {
            *v = T::default();
        }

        Ok(slice)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_arena() {
        let mut arena = Arena::new(16 * 1024).unwrap();
        let slice = arena.alloc(1024, 16).unwrap();
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
        let result = arena.alloc(size * 2, 16);
        assert!(result.is_err());
    }

    #[test]
    fn test_typed_arena() {
        let mut arena = TypedArena::<u32>::new(16 * 1024).unwrap();
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
