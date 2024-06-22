use super::error::PlainSerializerError;
use byteorder::{ReadBytesExt, LE};
use serde::de::{Deserialize, Deserializer, SeqAccess};
use std::{
    borrow::BorrowMut,
    io::{Cursor, Read},
    ops::DerefMut,
};

trait Todo<T> {
    fn todo(type_name: &'static str) -> Result<T, PlainSerializerError> {
        Err(PlainSerializerError::DeNotImplmented(type_name))
    }
}

#[derive(Debug)]
pub struct FieldOffset {
    pub field_name: &'static str,
    pub offset: usize,
    pub size: usize,
    pub inner_struct: Option<StructOffset>,
}

#[derive(Debug)]
pub struct StructOffset {
    pub name: &'static str,
    pub offset: usize,
    pub size: usize,
    pub fields: Vec<FieldOffset>,
}

impl StructOffset {
    fn last_struct(&mut self) -> &mut StructOffset {
        let mut current = self;

        loop {
            let tmp = current;
            let last = &mut tmp.fields.last_mut().map(|field| &mut field.inner_struct);
            if let Some(inner) = last {
                if let Some(inner) = inner {
                    current = inner;
                } else {
                    current = tmp;
                }
            } else {
                current = tmp;
                break;
            }
        }
        current
    }

    fn last_field_struct(&mut self) -> Option<&mut StructOffset> {
        (&mut self.fields.last_mut()?.inner_struct).as_mut()
    }
}

impl<T, R: Read> Todo<T> for &mut PlainDeserializer<R> {}

pub struct PlainDeserializer<R: Read> {
    reader: R,
    offsets: Option<StructOffset>,
    current_offset: usize,
}

impl<R: Read> PlainDeserializer<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            offsets: None,
            current_offset: 0,
        }
    }

    fn read_bytes(&mut self) -> Result<Vec<u8>, PlainSerializerError> {
        let len = self.reader.read_u16::<LE>()? as usize;
        self.advance_offset::<u16>();
        let mut vec = Vec::with_capacity(len);
        vec.resize(len, 0);

        self.reader.read_exact(&mut vec)?;
        self.current_offset += len;
        Ok(vec)
    }

    fn advance_offset<T: Sized>(&mut self) {
        let size = std::mem::size_of::<T>();
        // if let Some(last_struct) = self.offsets.last_mut() {
        //     if let Some(field) = last_struct.fields.last_mut() {
        //         field.size = self.current_offset - field.offset;
        //     }
        // }
        self.current_offset += size;
    }

    pub fn take_offsets(self) -> Option<StructOffset> {
        self.offsets
    }

    fn last_struct(&mut self) -> Option<&mut StructOffset> {
        let mut last_struct = self.offsets.as_mut()?;

        loop {
            let tmp = last_struct;
            match tmp.last_field_struct() {
                Some(inner) => {
                    last_struct = inner;
                }
                None => return Some(tmp),
            };
            // let tmp = last_struct;
            // if let Some(ref mut inner) = tmp.last_field_struct() {
            //     last_struct = *inner;
            // } else {
            //     last_struct = tmp;
            //     break;
            // }
        }
        Some(last_struct)
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
        self.advance_offset::<u8>();
        visitor.visit_bool(value != 0)
    }

    fn deserialize_i8<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        let value = self.reader.read_i8()?;
        self.advance_offset::<i8>();
        visitor.visit_i8(value)
    }

    fn deserialize_i16<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        let value = self.reader.read_i16::<LE>()?;
        self.advance_offset::<i16>();
        visitor.visit_i16(value)
    }

    fn deserialize_i32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        let value = self.reader.read_i32::<LE>()?;
        self.advance_offset::<i32>();
        visitor.visit_i32(value)
    }

    fn deserialize_i64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        let value = self.reader.read_i64::<LE>()?;
        self.advance_offset::<i64>();
        visitor.visit_i64(value)
    }

    fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        let value = self.reader.read_u8()?;
        self.advance_offset::<u8>();
        visitor.visit_u8(value)
    }

    fn deserialize_u16<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        let value = self.reader.read_u16::<LE>()?;
        self.advance_offset::<u16>();
        visitor.visit_u16(value)
    }

    fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        let value = self.reader.read_u32::<LE>()?;
        self.advance_offset::<u32>();
        visitor.visit_u32(value)
    }

    fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        let value = self.reader.read_u64::<LE>()?;
        self.advance_offset::<u64>();
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
        let is_some = self.reader.read_u8()? != 0;
        self.advance_offset::<u8>();
        if is_some {
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
        _visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        Self::todo("newtype_struct")
        // let start_offset = self.current_offset;
        // self.offsets.push(StructOffset {
        //     name,
        //     offset: start_offset,
        //     size: 0,
        //     fields: vec![],
        // });
        // visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        let count = self.reader.read_u16::<LE>()?;
        self.advance_offset::<u16>();
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
        name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        println!("deserializing struct {} with fields {:?}", name, fields);

        let new = StructOffset {
            name,
            offset: self.current_offset,
            size: 0,
            fields: vec![],
        };
        if let Some(offsets) = &mut self.offsets {
            let mut current_field = offsets.fields.last_mut().unwrap();
            while let Some(inner) = &mut current_field.inner_struct {
                current_field = inner.fields.last_mut().unwrap();
                if current_field.inner_struct.is_none() {
                    current_field.inner_struct = Some(new);
                    break;
                }
            }
        } else {
            self.offsets = Some(new)
        }

        visitor.visit_seq(PlainSeqDeserializer::new_with_fields(self, fields))
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
    fields: Option<&'static [&'static str]>,
}

impl<'a, R: Read> PlainSeqDeserializer<'a, R> {
    fn new(de: &'a mut PlainDeserializer<R>, count: usize) -> Self {
        Self {
            de,
            count,
            fields: None,
        }
    }

    fn new_with_fields(de: &'a mut PlainDeserializer<R>, fields: &'static [&'static str]) -> Self {
        Self {
            de,
            count: fields.len(),
            fields: Some(fields),
        }
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
        if let Some(fields) = self.fields {
            let mut last_struct = self
                .de
                .offsets
                .as_mut()
                .ok_or(PlainSerializerError::Custom(
                    "No structs are defined".into(),
                ))?;
            // loop {
            //     if let Some(field) = last_struct.fields.last_mut() {
            //         if let Some(inner) = &mut field.inner_struct {
            //             last_struct = inner
            //         }
            //     }
            //     let field_index = last_struct.fields.len();
            //     break;
            // }

            let field_name = fields[field_index];
            last_struct.fields.push(FieldOffset {
                field_name,
                offset: self.de.current_offset,
                size: 0,
                inner_struct: None,
            });
        }
        seed.deserialize(&mut *self.de).map(Some)
    }
}

pub fn read<'a, R: Read, T: Deserialize<'a>>(reader: R) -> Result<T, PlainSerializerError> {
    read_with_offsets(reader).map(|res| res.0)
}

pub fn from_bytes<'a, T: Deserialize<'a>>(bytes: &[u8]) -> Result<T, PlainSerializerError> {
    from_bytes_with_offsets(bytes).map(|res| res.0)
}

pub fn read_with_offsets<'a, R: Read, T: Deserialize<'a>>(
    reader: R,
) -> Result<(T, Vec<StructOffset>), PlainSerializerError> {
    let mut des = PlainDeserializer::new(reader);
    let value = T::deserialize(&mut des)?;
    let offsets = des.take_offsets();
    Ok((value, offsets))
}

pub fn from_bytes_with_offsets<'a, T: Deserialize<'a>>(
    bytes: &[u8],
) -> Result<(T, Vec<StructOffset>), PlainSerializerError> {
    let cursor = Cursor::new(bytes);
    read_with_offsets(cursor)
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

    #[test]
    fn test_offsets() {
        #[derive(serde::Deserialize, PartialEq, Eq, Debug)]
        struct InnerTest {
            num: i16,
        }
        #[derive(serde::Deserialize, PartialEq, Eq, Debug)]
        struct Test {
            array: [u8; 3],
            inner: Option<InnerTest>,
            inner2: InnerTest,
        }

        let test = b"abc\x01\x03\x00\x02\x00";

        let result = super::from_bytes_with_offsets::<Test>(test).unwrap();
        println!("{:?}", result.0);
        println!("{:?}", result.1);
    }
}
