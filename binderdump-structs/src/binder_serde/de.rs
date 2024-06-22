use super::error::PlainSerializerError;
use byteorder::{ReadBytesExt, LE};
use serde::de::{Deserialize, Deserializer, SeqAccess};
use std::io::{Cursor, Read};

trait Todo<T> {
    fn todo(type_name: &'static str) -> Result<T, PlainSerializerError> {
        Err(PlainSerializerError::DeNotImplmented(type_name))
    }
}

impl<T, R: Read> Todo<T> for &mut PlainDeserializer<R> {}

pub struct PlainDeserializer<R: Read> {
    reader: R,
}

impl<R: Read> PlainDeserializer<R> {
    pub fn new(reader: R) -> Self {
        Self { reader }
    }

    fn read_bytes(&mut self) -> Result<Vec<u8>, PlainSerializerError> {
        let len = self.reader.read_u16::<LE>()? as usize;
        let mut vec = Vec::with_capacity(len);
        vec.resize(len, 0);

        self.reader.read_exact(&mut vec)?;
        Ok(vec)
    }
}

impl<'de, R: Read> Deserializer<'de> for &mut PlainDeserializer<R> {
    type Error = PlainSerializerError;

    fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        Self::todo("any")
    }

    fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        let value = self.reader.read_u8()?;
        visitor.visit_bool(value != 0)
    }

    fn deserialize_i8<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        let value = self.reader.read_i8()?;
        visitor.visit_i8(value)
    }

    fn deserialize_i16<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        let value = self.reader.read_i16::<LE>()?;
        visitor.visit_i16(value)
    }

    fn deserialize_i32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        let value = self.reader.read_i32::<LE>()?;
        visitor.visit_i32(value)
    }

    fn deserialize_i64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        let value = self.reader.read_i64::<LE>()?;
        visitor.visit_i64(value)
    }

    fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        let value = self.reader.read_u8()?;
        visitor.visit_u8(value)
    }

    fn deserialize_u16<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        let value = self.reader.read_u16::<LE>()?;
        visitor.visit_u16(value)
    }

    fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        let value = self.reader.read_u32::<LE>()?;
        visitor.visit_u32(value)
    }

    fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        let value = self.reader.read_u64::<LE>()?;
        visitor.visit_u64(value)
    }

    fn deserialize_f32<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        Self::todo("f32")
    }

    fn deserialize_f64<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        Self::todo("f64")
    }

    fn deserialize_char<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        Self::todo("char")
    }

    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        self.deserialize_string(visitor)
    }

    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        let bytes = self.read_bytes()?;
        let str = String::from_utf8(bytes)
            .map_err(|err| PlainSerializerError::Utf8Error(err.utf8_error()))?;
        visitor.visit_string(str)
    }

    fn deserialize_bytes<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        self.deserialize_byte_buf(visitor)
    }

    fn deserialize_byte_buf<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_byte_buf(self.read_bytes()?)
    }

    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        if self.reader.read_u8()? != 0 {
            visitor.visit_some(self)
        } else {
            visitor.visit_none()
        }
    }

    fn deserialize_unit<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        Self::todo("unit")
    }

    fn deserialize_unit_struct<V>(
        self,
        _name: &'static str,
        _visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        Self::todo("unit_struct")
    }

    fn deserialize_newtype_struct<V>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        let count = self.reader.read_u16::<LE>()?;
        visitor.visit_seq(PlainSeqDeserializer::new(self, count as usize))
    }

    fn deserialize_tuple<V>(self, len: usize, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_seq(PlainSeqDeserializer::new(self, len))
    }

    fn deserialize_tuple_struct<V>(
        self,
        _name: &'static str,
        _len: usize,
        _visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        Self::todo("tuple_struct")
    }

    fn deserialize_map<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        Self::todo("map")
    }

    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_seq(PlainSeqDeserializer::new(self, fields.len()))
    }

    fn deserialize_enum<V>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        Self::todo("enum")
    }

    fn deserialize_identifier<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        Self::todo("identifier")
    }

    fn deserialize_ignored_any<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        Self::todo("ignored_any")
    }
}

struct PlainSeqDeserializer<'a, R: Read> {
    de: &'a mut PlainDeserializer<R>,
    count: usize,
}

impl<'a, R: Read> PlainSeqDeserializer<'a, R> {
    fn new(de: &'a mut PlainDeserializer<R>, count: usize) -> Self {
        Self { de, count }
    }
}
impl<'a, 'de, R: Read> SeqAccess<'de> for PlainSeqDeserializer<'a, R> {
    type Error = PlainSerializerError;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Self::Error>
    where
        T: serde::de::DeserializeSeed<'de>,
    {
        if self.count == 0 {
            return Ok(None);
        }
        self.count -= 1;
        seed.deserialize(&mut *self.de).map(Some)
    }
}

pub fn read<'a, R: Read, T: Deserialize<'a>>(reader: R) -> Result<T, PlainSerializerError> {
    let mut des = PlainDeserializer::new(reader);
    T::deserialize(&mut des)
}

pub fn from_bytes<'a, T: Deserialize<'a>>(bytes: &[u8]) -> Result<T, PlainSerializerError> {
    let cursor = Cursor::new(bytes);
    read(cursor)
}

mod test {
    #[test]
    fn test_struct() {
        #[derive(serde::Deserialize, Eq, PartialEq, Debug)]
        struct Test {
            int: u32,
            seq: Vec<u8>,
        }

        let test = b"\x03\x00\x00\x00\x03\x00\x01\x02\x03";

        let expected = Test {
            int: 3,
            seq: vec![1, 2, 3],
        };

        let result = super::from_bytes::<Test>(test).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_enum() {
        #[allow(unused)]
        #[derive(serde_repr::Deserialize_repr, Debug, Eq, PartialEq)]
        #[repr(i16)]
        enum Test {
            ZERO,
            ONE,
            TWO,
        }

        let test = b"\x01\x00";
        assert_eq!(super::from_bytes::<Test>(test).unwrap(), Test::ONE);
    }

    #[test]
    fn test_option() {
        #[derive(serde::Deserialize, PartialEq, Eq, Debug)]
        struct Test {
            option: Option<i32>,
            option2: Option<Vec<u8>>,
        }

        let test = b"\x01\x05\x00\x00\x00\x00";
        let expected = Test {
            option: Some(5),
            option2: None,
        };

        assert_eq!(super::from_bytes::<Test>(test).unwrap(), expected);
    }

    #[test]
    fn test_array() {
        #[derive(serde::Deserialize, PartialEq, Eq, Debug)]
        struct Test {
            array: [u8; 3],
        }

        let test = b"abc";
        let expected = Test {
            array: [b'a', b'b', b'c'],
        };

        assert_eq!(super::from_bytes::<Test>(test).unwrap(), expected);
    }
}
