use super::error::PlainSerializerError;
use serde::{
    ser::{self, Impossible, SerializeSeq, SerializeStruct, SerializeTuple},
    Serialize,
};
use std::{
    io::{Cursor, Write},
    ops::DerefMut,
};

pub struct PlainSerializer<W: Write> {
    writer: W,
}

trait Todo<T> {
    fn todo(type_name: &'static str) -> Result<T, PlainSerializerError> {
        Err(PlainSerializerError::SerNotImplmented(type_name))
    }
}

impl<T, W: Write> Todo<T> for &mut PlainSerializer<W> {}

impl<W: Write> PlainSerializer<W> {
    pub fn new(writer: W) -> Self {
        Self { writer }
    }
}

impl<W: Write> ser::Serializer for &mut PlainSerializer<W> {
    type Ok = ();

    type Error = PlainSerializerError;

    type SerializeSeq = Self;

    type SerializeTuple = Self;

    type SerializeTupleStruct = Impossible<Self::Ok, Self::Error>;

    type SerializeTupleVariant = Impossible<Self::Ok, Self::Error>;

    type SerializeMap = Impossible<Self::Ok, Self::Error>;

    type SerializeStruct = Self;

    type SerializeStructVariant = Impossible<Self::Ok, Self::Error>;

    fn serialize_bool(self, v: bool) -> Result<Self::Ok, Self::Error> {
        self.serialize_u8(v as u8)
    }

    fn serialize_i8(self, v: i8) -> Result<Self::Ok, Self::Error> {
        self.writer.write_all(&v.to_le_bytes())?;
        Ok(())
    }

    fn serialize_i16(self, v: i16) -> Result<Self::Ok, Self::Error> {
        self.writer.write_all(&v.to_le_bytes())?;
        Ok(())
    }

    fn serialize_i32(self, v: i32) -> Result<Self::Ok, Self::Error> {
        self.writer.write_all(&v.to_le_bytes())?;
        Ok(())
    }

    fn serialize_i64(self, v: i64) -> Result<Self::Ok, Self::Error> {
        self.writer.write_all(&v.to_le_bytes())?;
        Ok(())
    }

    fn serialize_u8(self, v: u8) -> Result<Self::Ok, Self::Error> {
        self.writer.write_all(&v.to_le_bytes())?;
        Ok(())
    }

    fn serialize_u16(self, v: u16) -> Result<Self::Ok, Self::Error> {
        self.writer.write_all(&v.to_le_bytes())?;
        Ok(())
    }

    fn serialize_u32(self, v: u32) -> Result<Self::Ok, Self::Error> {
        self.writer.write_all(&v.to_le_bytes())?;
        Ok(())
    }

    fn serialize_u64(self, v: u64) -> Result<Self::Ok, Self::Error> {
        self.writer.write_all(&v.to_le_bytes())?;
        Ok(())
    }

    fn serialize_f32(self, _v: f32) -> Result<Self::Ok, Self::Error> {
        Self::todo("f32")
    }

    fn serialize_f64(self, _v: f64) -> Result<Self::Ok, Self::Error> {
        Self::todo("f64")
    }

    fn serialize_char(self, _v: char) -> Result<Self::Ok, Self::Error> {
        Self::todo("char")
    }

    fn serialize_str(self, v: &str) -> Result<Self::Ok, Self::Error> {
        self.serialize_bytes(v.as_bytes())
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<Self::Ok, Self::Error> {
        let len: u32 = v.len().try_into().map_err(PlainSerializerError::TooBig)?;
        self.serialize_u32(len)?;
        for byte in v {
            self.serialize_u8(*byte)?;
        }
        Ok(())
    }

    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        self.serialize_u8(0)
    }

    fn serialize_some<T>(self, value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        self.serialize_u8(1)?;
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        Self::todo("unit")
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Self::Error> {
        Self::todo("unit_struct")
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        Self::todo("unit_variant")
    }

    fn serialize_newtype_struct<T>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T>(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        Self::todo("newtype_variant")
    }

    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        let len = len.ok_or(PlainSerializerError::UnknownLength)?;
        let len: u32 = len.try_into().map_err(PlainSerializerError::TooBig)?;
        self.serialize_u32(len)?;
        Ok(self)
    }

    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        Ok(self)
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        Self::todo("tuple_struct")
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        Self::todo("tuple_variant")
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        Self::todo("map")
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        Ok(self)
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        Self::todo("struct_variant")
    }
}

impl<W: Write> SerializeSeq for &mut PlainSerializer<W> {
    type Ok = ();

    type Error = PlainSerializerError;

    fn serialize_element<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(self.deref_mut())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

impl<W: Write> SerializeStruct for &mut PlainSerializer<W> {
    type Ok = ();

    type Error = PlainSerializerError;

    fn serialize_field<T>(&mut self, _key: &'static str, value: &T) -> Result<(), Self::Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(self.deref_mut())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

impl<W: Write> SerializeTuple for &mut PlainSerializer<W> {
    type Ok = ();

    type Error = PlainSerializerError;

    fn serialize_element<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(self.deref_mut())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

pub fn write<W: Write, T: Serialize>(writer: W, value: &T) -> Result<(), PlainSerializerError> {
    let mut serializer = PlainSerializer::new(writer);
    value.serialize(&mut serializer)
}

pub fn to_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, PlainSerializerError> {
    let mut output = vec![];
    let cursor = Cursor::new(&mut output);

    write(cursor, value)?;
    Ok(output)
}

#[cfg(test)]
mod test {
    use super::to_bytes;

    #[test]
    fn test_struct() {
        #[derive(serde::Serialize)]
        struct Test {
            int: u32,
            seq: Vec<u8>,
        }

        let test = Test {
            int: 3,
            seq: vec![1, 2, 3],
        };

        let expected = b"\x03\x00\x00\x00\x03\x00\x00\x00\x01\x02\x03";
        assert_eq!(super::to_bytes(&test).unwrap(), expected);
    }

    #[test]
    fn test_empty_seq() {
        #[derive(serde::Serialize)]
        struct Test {
            seq: Vec<u8>,
        }

        let test = Test { seq: vec![] };

        let expected = b"\x00\x00\x00\x00";
        assert_eq!(super::to_bytes(&test).unwrap(), expected);
    }

    #[test]
    fn test_enum() {
        #[allow(unused)]
        #[derive(serde_repr::Serialize_repr)]
        #[repr(i16)]
        enum Test {
            ZERO,
            ONE,
            TWO,
        }

        let expected = b"\x01\x00";
        assert_eq!(super::to_bytes(&Test::ONE).unwrap(), expected);
    }

    #[test]
    fn test_option() {
        #[derive(serde::Serialize)]
        struct Test {
            option: Option<i32>,
            option2: Option<Vec<u8>>,
        }

        let test = Test {
            option: Some(5),
            option2: None,
        };

        let expected = b"\x01\x05\x00\x00\x00\x00";
        assert_eq!(super::to_bytes(&test).unwrap(), expected);
    }

    #[test]
    fn test_array() {
        #[derive(serde::Serialize)]
        struct Test {
            array: [u8; 3],
        }

        let test = Test {
            array: [b'a', b'b', b'c'],
        };
        let expected = b"abc";

        assert_eq!(super::to_bytes(&test).unwrap(), expected);
    }

    #[test]
    fn serialize_bytes_over_u16_max_does_not_overflow() {
        let large: Vec<u8> = vec![0xab; 70_000]; // > u16::MAX (65535)
        let encoded = to_bytes(&large).expect("must serialize >64KB without overflow");
        // first 4 bytes = u32 LE length
        assert_eq!(&encoded[..4], &(70_000u32).to_le_bytes());
        assert_eq!(encoded.len(), 4 + 70_000);
    }

    #[test]
    fn round_trip_large_seq() {
        // Vec<u32> of 70k elements: length is u32, each element is u32.
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct Wrapper {
            items: Vec<u32>,
        }
        let w = Wrapper {
            items: (0u32..70_000).collect(),
        };
        let encoded = to_bytes(&w).unwrap();
        // first 4 bytes = u32 LE count = 70000
        assert_eq!(&encoded[..4], &(70_000u32).to_le_bytes());
        // round-trip via the deserializer
        let decoded: Wrapper = crate::binder_serde::from_bytes(&encoded).unwrap();
        assert_eq!(w, decoded);
    }
}
