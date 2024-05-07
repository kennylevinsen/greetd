use std::{default::Default, ffi::CString};

/// Scrambling overwrites a buffers content with the default value. Useful to
/// avoid leaving behind a heap littered with old secrets.
pub trait Scrambler {
    fn scramble(&mut self);
}

impl<T: Default> Scrambler for Vec<T> {
    fn scramble(&mut self) {
        let cap = self.capacity();
        self.truncate(0);
        for _ in 0..cap {
            self.push(Default::default())
        }
        self.truncate(0);
    }
}

impl Scrambler for String {
    fn scramble(&mut self) {
        let v = unsafe { self.as_mut_vec() };
        for idx in 0..v.len() {
            v[idx] = 0
        }
        self.truncate(0);
    }
}

impl Scrambler for CString {
    fn scramble(&mut self) {
        unsafe {
            let ptr = self.as_ptr();
            let mut offset = 0;

            while *ptr.offset(offset) != 0 {
                *(ptr.offset(offset) as *mut i8) = 0;
                offset += 1;
            }
        }
    }
}
