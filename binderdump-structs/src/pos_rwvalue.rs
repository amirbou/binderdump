use binrw::prelude::*;
use binrw::Endian;
use std::fmt;
use std::io::{Read, Seek};
pub struct PosRWValue<T> {
    /// The read value.
    pub val: T,

    /// The byte position of the start of the value.
    pub pos: u64,
}

impl<T: BinRead> BinRead for PosRWValue<T> {
    type Args<'a> = T::Args<'a>;

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        endian: Endian,
        args: Self::Args<'_>,
    ) -> BinResult<Self> {
        let pos = reader.stream_position()?;

        Ok(PosRWValue {
            pos,
            val: T::read_options(reader, endian, args)?,
        })
    }
}

impl<T: BinWrite> BinWrite for PosRWValue<T> {
    type Args<'a> = T::Args<'a>;

    fn write_options<W: std::io::Write + Seek>(
        &self,
        writer: &mut W,
        endian: Endian,
        args: Self::Args<'_>,
    ) -> BinResult<()> {
        self.val.write_options(writer, endian, args)
    }
}

impl<T: Default> Default for PosRWValue<T> {
    fn default() -> Self {
        Self {
            val: Default::default(),
            pos: Default::default(),
        }
    }
}

impl<T> From<T> for PosRWValue<T> {
    fn from(val: T) -> Self {
        Self {
            val,
            pos: Default::default(),
        }
    }
}

impl<T> core::ops::Deref for PosRWValue<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.val
    }
}

impl<T> core::ops::DerefMut for PosRWValue<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.val
    }
}

impl<T: fmt::Debug> fmt::Debug for PosRWValue<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.val.fmt(f)
    }
}

impl<T: Clone> Clone for PosRWValue<T> {
    fn clone(&self) -> Self {
        Self {
            val: self.val.clone(),
            pos: self.pos,
        }
    }
}

impl<U, T: PartialEq<U>> PartialEq<U> for PosRWValue<T> {
    fn eq(&self, other: &U) -> bool {
        self.val == *other
    }
}
