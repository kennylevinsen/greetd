use std::default::Default;

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
        let cap = self.capacity();
        self.truncate(0);
        for _ in 0..cap {
            self.push(Default::default())
        }
        self.truncate(0);
    }
}
