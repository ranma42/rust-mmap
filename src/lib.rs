extern crate libc;

use std::io::{Error,ErrorKind};

/*
Only allow some combinations:
 R, RW, RX

The other four combinations are not allowed for the following reasons:
 - 0: not being able to access the data can be achieved without mapping anything at all
 - W: being able to write data without being able to read it makes little sense and cannot be enforced in Rust
 - X: being able to run code without reading it makes no sense
 - WX, RWX: modifying code which can be running at the same time is a bad idea
*/

pub struct MemoryMapFlags<'a> {
    base: *mut libc::c_void,
    file: Option<&'a std::fs::File>,
    offset: usize,
    len: usize,
    shared: bool,
    exec: bool,
}

impl<'a> MemoryMapFlags<'a> {
    pub fn new() -> MemoryMapFlags<'a> {
        MemoryMapFlags {
            base: std::ptr::null_mut(),
            file: None,
            offset: 0,
            len: 0,
            shared: true,
            exec: false,
        }
    }

    pub fn base(&mut self, base: *mut libc::c_void) -> &mut MemoryMapFlags<'a> {
        self.base = base; self
    }

    pub fn offset(&mut self, offset: usize) -> &mut MemoryMapFlags<'a> {
        self.offset = offset; self
    }

    pub fn len(&mut self, len: usize) -> &mut MemoryMapFlags<'a> {
        self.len = len; self
    }

    pub fn shared(&mut self, shared: bool) -> &mut MemoryMapFlags<'a> {
        self.shared = shared; self
    }

    pub fn exec(&mut self, exec: bool) -> &mut MemoryMapFlags<'a> {
        self.exec = exec; self
    }

    pub fn anon(&mut self) -> &mut MemoryMapFlags<'a> {
        self.file = None; self
    }

    pub fn file(&mut self, file: &'a std::fs::File) -> &mut MemoryMapFlags<'a> {
        self.file = Some(file); self
    }

    pub fn map_readonly(&self) -> Result<ConstMemoryMap, Error> {
        unsafe { UnsafeMemoryMap::new(self, false).map(ConstMemoryMap) }
    }

    pub fn map_readwrite(&self) -> Result<MutMemoryMap, Error> {
        unsafe { UnsafeMemoryMap::new(self, true).map(MutMemoryMap) }
    }
}


pub struct ConstMemoryMap(UnsafeMemoryMap);

impl<T> AsRef<[T]> for ConstMemoryMap {
    fn as_ref(&self) -> &[T] {
        unsafe { self.0.as_ref() }
    }
}


pub struct MutMemoryMap(UnsafeMemoryMap);

impl<T> AsRef<[T]> for MutMemoryMap {
    fn as_ref(&self) -> &[T] {
        unsafe { self.0.as_ref() }
    }
}

impl<T> AsMut<[T]> for MutMemoryMap {
    fn as_mut(&mut self) -> &mut [T] {
        unsafe { self.0.as_mut() }
    }
}


struct UnsafeMemoryMap {
    ptr: *mut libc::c_void,
    len: libc::size_t,
}

impl Drop for UnsafeMemoryMap {
    #[cfg(unix)]
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr, self.len);
            // Ignore any error, memory safety will ensure that those
            // pages are not accessed anymore
        }

        // Just in case, be paranoid about data structure contents
        self.ptr = libc::MAP_FAILED;
        self.len = 0;
    }

    #[cfg(windows)]
    fn drop(&mut self) {
        unsafe {
            libc::UnmapViewOfFile(self.ptr);
            // Ignore any error, memory safety will ensure that those
            // pages are not accessed anymore
        }

        // Just in case, be paranoid about data structure contents
        self.ptr = std::ptr::null_mut();
        self.len = 0;
    }
}

impl UnsafeMemoryMap {
    #[cfg(unix)]
    pub unsafe fn new(flags: &MemoryMapFlags, rw: bool) -> Result<UnsafeMemoryMap, Error> {
        let len = flags.len as libc::size_t;
        let offset = flags.offset as libc::off_t;

        if len as usize != flags.len {
            return Err(Error::new(ErrorKind::InvalidInput, "Illegal length"))
        } else if offset as usize != flags.offset {
            return Err(Error::new(ErrorKind::InvalidInput, "Illegal offset"))
        }

        let prot =
            libc::PROT_READ |
            if rw { libc::PROT_WRITE } else { 0 } |
            if flags.exec { libc::PROT_EXEC } else { 0 };

        let map_flags =
            if flags.shared { libc::MAP_SHARED } else { libc::MAP_PRIVATE } |
            match flags.file { None => libc::MAP_ANON, Some(_) => libc::MAP_FILE };

        let fd = flags.file.map_or(-1, |f| std::os::unix::io::AsRawFd::as_raw_fd(f));

        let ptr = libc::mmap(flags.base, len, prot, map_flags, fd, offset);
        if ptr == libc::MAP_FAILED {
            Err(Error::last_os_error())
        } else {
            Ok(UnsafeMemoryMap { ptr: ptr, len: len })
        }
    }

    #[cfg(windows)]
    pub unsafe fn new(flags: &MemoryMapFlags, rw: bool) -> Result<UnsafeMemoryMap, Error> {
        #[inline]
        fn split(x: u64) -> (libc::DWORD, libc::DWORD) {
            let hi = (x >> 32) as libc::DWORD;
            let lo = (x & 0xffffffff) as libc::DWORD;
            (hi, lo)
        }

        let len = flags.len as u64 as libc::SIZE_T;
        let offset = flags.offset as u64;

        if len as usize != flags.len {
            return Err(Error::new(ErrorKind::InvalidInput, "Illegal length"))
        } else if offset as usize != flags.offset {
            return Err(Error::new(ErrorKind::InvalidInput, "Illegal offset"))
        }

        let file = flags.file.map_or(libc::INVALID_HANDLE_VALUE,
                                     |f| std::os::windows::io::AsRawHandle::as_raw_handle(f) as *mut libc::c_void);

        let (protect, access) = match (flags.exec, rw, flags.shared) {
            (false, false,     _) => (libc::PAGE_READONLY, libc::FILE_MAP_READ),
            (false,  true,  true) => (libc::PAGE_READWRITE, libc::FILE_MAP_WRITE),
            (false,  true, false) => (libc::PAGE_WRITECOPY, libc::FILE_MAP_COPY),
            ( true, false,     _) => (libc::PAGE_EXECUTE_READ, libc::FILE_MAP_READ | libc::FILE_MAP_EXECUTE),
            ( true,  true,  true) => (libc::PAGE_EXECUTE_READWRITE, libc::FILE_MAP_WRITE | libc::FILE_MAP_EXECUTE),
            ( true,  true, false) => (libc::PAGE_EXECUTE_WRITECOPY, libc::FILE_MAP_COPY | libc::FILE_MAP_EXECUTE),
        };

        let (size_hi, size_lo) = split(len as u64);
        let (off_hi, off_lo) = split(offset as u64);

        let map = libc::CreateFileMappingW(file,
                                           std::ptr::null_mut(),
                                           protect,
                                           size_hi, size_lo,
                                           std::ptr::null());
        let ptr = libc::MapViewOfFile(map, access, off_hi, off_lo, len);
        if ptr == std::ptr::null_mut() {
            Err(Error::last_os_error())
        } else {
            Ok(UnsafeMemoryMap { ptr: ptr, len: len })
        }
    }

    fn slice_len<T>(&self) -> usize {
        (self.len as usize) / std::mem::size_of::<T>()
    }

    pub unsafe fn as_ref<T>(&self) -> &[T] {
        std::slice::from_raw_parts(self.ptr as *const T, self.slice_len::<T>())
    }

    pub unsafe fn as_mut<T>(&mut self) -> &mut [T] {
        std::slice::from_raw_parts_mut(self.ptr as *mut T, self.slice_len::<T>())
    }
}

#[test]
fn anon_rw() {
    if let Ok(mut map) = MemoryMapFlags::new()
        .len(4096)
        .anon()
        .map_readwrite() {
        let buf: &mut [u8] = map.as_mut();
        buf[0] = 42;
        assert!(buf[0] == 42);
    }
}
