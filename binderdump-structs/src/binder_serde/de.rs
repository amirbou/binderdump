use super::error::PlainSerializerError;
pub use binderdump_trait::{FieldOffset, StructOffset};
use byteorder::{ReadBytesExt, LE};
use serde::de::{Deserialize, Deserializer, SeqAccess};
use std::{
    borrow::Cow,
    io::{Cursor, Read},
};

trait Todo<T> {
    fn todo(type_name: &'static str) -> Result<T, PlainSerializerError> {
        Err(PlainSerializerError::DeNotImplmented(type_name))
    }
}

struct OffsetDeserializer {
    structs_stack: Vec<StructOffset>,
    fields_stack: Vec<&'static [&'static str]>,
    // Parallel stack of "this struct frame is a Vec<T: struct> element".
    // Set by `mark_seq_element` (called from PlainSeqDeserializer in SEQ mode
    // right before each element's `deserialize`) and consumed in begin_struct.
    is_seq_element_stack: Vec<bool>,
    pending_seq_element: bool,
    result: Option<StructOffset>,
}

impl OffsetDeserializer {
    pub fn new() -> Self {
        Self {
            structs_stack: vec![],
            fields_stack: vec![],
            is_seq_element_stack: vec![],
            pending_seq_element: false,
            result: None,
        }
    }

    pub fn mark_seq_element(&mut self) {
        self.pending_seq_element = true;
    }

    pub fn begin_struct(
        &mut self,
        name: &'static str,
        fields: &'static [&'static str],
        offset: usize,
    ) -> Result<(), PlainSerializerError> {
        if self.result.is_some() {
            return Err(PlainSerializerError::TooManyStructs);
        }
        self.structs_stack.push(StructOffset {
            name,
            offset,
            size: 0,
            fields: vec![],
        });
        self.fields_stack.push(fields);
        self.is_seq_element_stack.push(self.pending_seq_element);

        Ok(())
    }

    fn get_last_struct(
        structs_stack: &mut Vec<StructOffset>,
    ) -> Result<&mut StructOffset, PlainSerializerError> {
        structs_stack
            .last_mut()
            .ok_or(PlainSerializerError::EmptyStructStack)
    }

    pub fn add_field(&mut self, offset: usize) -> Result<(), PlainSerializerError> {
        let last_struct = Self::get_last_struct(&mut self.structs_stack)?;
        let last_fields = self
            .fields_stack
            .pop()
            .ok_or(PlainSerializerError::EmptyFieldsStack)?;
        if last_fields.len() == 0 {
            return Err(PlainSerializerError::TooManyFields);
        }
        let field_name = last_fields[0];
        self.fields_stack.push(&last_fields[1..]);

        if let Some(prev_field) = last_struct.fields.last_mut() {
            prev_field.size = offset - prev_field.offset;
        }
        last_struct.fields.push(FieldOffset {
            field_name: Cow::Borrowed(field_name),
            offset,
            size: 0,
            inner_struct: None,
        });

        Ok(())
    }

    fn add_psuedo(
        &mut self,
        offset: usize,
        size: usize,
        suffix: &str,
        keep_previous_field: bool,
    ) -> Result<(), PlainSerializerError> {
        let last_struct = Self::get_last_struct(&mut self.structs_stack)?;
        let mut prev_field = last_struct
            .fields
            .pop()
            .ok_or(PlainSerializerError::TooManyFields)?;

        let field_name = format!("{}{}", prev_field.field_name, suffix);
        last_struct.fields.push(FieldOffset {
            field_name: Cow::Owned(field_name),
            offset,
            size: size,
            inner_struct: None,
        });
        if keep_previous_field {
            prev_field.offset += size;
            last_struct.fields.push(prev_field);
        }
        Ok(())
    }

    pub fn add_option(
        &mut self,
        offset: usize,
        size: usize,
        is_some: bool,
    ) -> Result<(), PlainSerializerError> {
        // if we got a "None" we want to skip the current field
        self.add_psuedo(offset, size, "_is_present", is_some)
    }

    pub fn add_len(&mut self, offset: usize, size: usize) -> Result<(), PlainSerializerError> {
        // TODO - if len == 0, keep_previous_field should be false?
        self.add_psuedo(offset, size, "_len", true)
    }

    pub fn finish_struct(&mut self, offset: usize) -> Result<(), PlainSerializerError> {
        let mut finished_struct = self
            .structs_stack
            .pop()
            .ok_or(PlainSerializerError::EmptyStructStack)?;
        let remaining_fields_count = self
            .fields_stack
            .pop()
            .ok_or(PlainSerializerError::EmptyStructStack)?
            .len();
        if remaining_fields_count != 0 {
            return Err(PlainSerializerError::TooLittleFields);
        }
        let is_seq_element = self.is_seq_element_stack.pop().unwrap_or(false);
        if let Some(last_field) = finished_struct.fields.last_mut() {
            last_field.size = offset - last_field.offset;
        }
        finished_struct.size = offset - finished_struct.offset;

        match self.structs_stack.last_mut() {
            Some(last_struct) => {
                let last_field = last_struct
                    .fields
                    .last_mut()
                    .ok_or(PlainSerializerError::NoFields)?;
                if is_seq_element && last_field.inner_struct.is_some() {
                    // Subsequent Vec<T: struct> element. Append a sibling field
                    // reusing the same field_name so the dissector resolves the
                    // same hf/ett registrations as element 0.
                    let elem_name = last_field.field_name.clone();
                    last_struct.fields.push(FieldOffset {
                        field_name: elem_name,
                        offset: finished_struct.offset,
                        size: finished_struct.size,
                        inner_struct: Some(finished_struct),
                    });
                } else if last_field.inner_struct.is_none() {
                    // First Vec<T: struct> element OR a regular nested struct field.
                    last_field.inner_struct = Some(finished_struct);
                } else {
                    return Err(PlainSerializerError::DoubleInnerStruct);
                }
            }
            None => self.result = Some(finished_struct),
        }
        Ok(())
    }

    pub fn take(self) -> Result<StructOffset, PlainSerializerError> {
        if !self.fields_stack.is_empty() {
            return Err(PlainSerializerError::UnexpectedFields);
        }
        if !self.structs_stack.is_empty() {
            return Err(PlainSerializerError::UnexpectedStruct);
        }
        if !self.is_seq_element_stack.is_empty() {
            return Err(PlainSerializerError::UnexpectedStruct);
        }

        self.result.ok_or(PlainSerializerError::NoResult)
    }
}

impl<T, R: Read> Todo<T> for &mut PlainDeserializer<R> {}

pub struct PlainDeserializer<R: Read> {
    reader: R,
    offsets_deserializer: OffsetDeserializer,
    current_offset: usize,
}

impl<R: Read> PlainDeserializer<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            offsets_deserializer: OffsetDeserializer::new(),
            current_offset: 0,
        }
    }

    fn read_bytes(&mut self) -> Result<Vec<u8>, PlainSerializerError> {
        self.offsets_deserializer
            .add_len(self.current_offset, std::mem::size_of::<u16>())?;
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
        self.current_offset += size;
    }

    pub fn take_offsets(self) -> Result<StructOffset, PlainSerializerError> {
        self.offsets_deserializer.take()
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
        self.offsets_deserializer.add_option(
            self.current_offset - std::mem::size_of::<u8>(),
            std::mem::size_of::<u8>(),
            is_some,
        )?;
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
    }

    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        self.offsets_deserializer
            .add_len(self.current_offset, std::mem::size_of::<u16>())?;
        let count = self.reader.read_u16::<LE>()?;
        self.advance_offset::<u16>();
        visitor.visit_seq(PlainSeqDeserializer::new_seq(self, count as usize))
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
        self.offsets_deserializer
            .begin_struct(name, fields, self.current_offset)?;
        visitor.visit_seq(PlainSeqDeserializer::new_struct(self, fields))
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

enum SeqMode {
    SEQ,    // only stops iteration when return value is Ok(None)
    STRUCT, // requires calls to `offsets_deserializer`
    OTHER,  // like struct but without `offsets_deserializer`
}
struct PlainSeqDeserializer<'a, R: Read> {
    de: &'a mut PlainDeserializer<R>,
    count: usize,
    mode: SeqMode,
}

impl<'a, R: Read> PlainSeqDeserializer<'a, R> {
    fn new(de: &'a mut PlainDeserializer<R>, count: usize) -> Self {
        Self {
            de,
            count,
            mode: SeqMode::OTHER,
        }
    }

    fn new_seq(de: &'a mut PlainDeserializer<R>, count: usize) -> Self {
        Self {
            de,
            count,
            mode: SeqMode::SEQ,
        }
    }

    fn new_struct(de: &'a mut PlainDeserializer<R>, fields: &'static [&'static str]) -> Self {
        Self {
            de,
            count: fields.len(),
            mode: SeqMode::STRUCT,
        }
    }
}
impl<'a, 'de, R: Read> SeqAccess<'de> for PlainSeqDeserializer<'a, R> {
    type Error = PlainSerializerError;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Self::Error>
    where
        T: serde::de::DeserializeSeed<'de>,
    {
        if matches!(self.mode, SeqMode::STRUCT) {
            self.de
                .offsets_deserializer
                .add_field(self.de.current_offset)?;
        }
        if matches!(self.mode, SeqMode::SEQ) && self.count == 0 {
            return Ok(None);
        }
        if matches!(self.mode, SeqMode::SEQ) {
            // Tag the next struct frame as a Vec<T: struct> element so its
            // finish_struct knows to append a sibling instead of attaching to
            // the parent's last field.
            self.de.offsets_deserializer.mark_seq_element();
        }
        let result = seed.deserialize(&mut *self.de).map(Some);
        if matches!(self.mode, SeqMode::STRUCT) && self.count == 1 {
            self.de
                .offsets_deserializer
                .finish_struct(self.de.current_offset)?;
        }

        self.count -= 1;
        result
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
) -> Result<(T, Result<StructOffset, PlainSerializerError>), PlainSerializerError> {
    let mut des = PlainDeserializer::new(reader);
    let value = T::deserialize(&mut des)?;
    let offsets = des.take_offsets();
    Ok((value, offsets))
}

pub fn from_bytes_with_offsets<'a, T: Deserialize<'a>>(
    bytes: &[u8],
) -> Result<(T, Result<StructOffset, PlainSerializerError>), PlainSerializerError> {
    let cursor = Cursor::new(bytes);
    read_with_offsets(cursor)
}

#[cfg(test)]
mod test {
    use crate::binder_serde::{
        de::{FieldOffset, StructOffset},
        from_bytes_with_offsets,
    };
    use pretty_assertions::assert_eq;
    use serde::Deserialize;
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
    fn test_empty_seq() {
        #[derive(serde::Deserialize, Eq, PartialEq, Debug)]
        struct Test {
            seq: Vec<u8>,
        }

        let test = b"\x00\x00";

        let expected = Test { seq: vec![] };

        let (result, offsets) = super::from_bytes_with_offsets::<Test>(test).unwrap();
        assert_eq!(result, expected);

        let expected_offets = StructOffset {
            name: "Test",
            offset: 0,
            size: 2,
            fields: vec![
                FieldOffset {
                    field_name: "seq_len".into(),
                    offset: 0,
                    size: 2,
                    inner_struct: None,
                },
                FieldOffset {
                    field_name: "seq".into(),
                    offset: 2,
                    size: 0,
                    inner_struct: None,
                },
            ],
        };
        assert_eq!(offsets.unwrap(), expected_offets);
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
        struct InnerInnerTest {
            num: u8,
        }

        #[derive(serde::Deserialize, PartialEq, Eq, Debug)]
        struct InnerTest {
            num: i16,
            inner: InnerInnerTest,
        }
        #[derive(serde::Deserialize, PartialEq, Eq, Debug)]
        struct Test {
            array: [u8; 3],
            bytes: Vec<u8>,
            inner: Option<InnerTest>,
            inner2: InnerTest,
        }

        let test = b"abc\x01\x00\x01\x01\x03\x00\x01\x02\x00\x06";

        let (result, offsets) = super::from_bytes_with_offsets::<Test>(test).unwrap();
        let expected = Test {
            array: [b'a', b'b', b'c'],
            bytes: vec![1],
            inner: Some(InnerTest {
                num: 3,
                inner: InnerInnerTest { num: 1 },
            }),
            inner2: InnerTest {
                num: 2,
                inner: InnerInnerTest { num: 6 },
            },
        };
        assert_eq!(result, expected);

        let expected_offsets = StructOffset {
            name: "Test",
            offset: 0,
            size: 13,
            fields: vec![
                FieldOffset {
                    field_name: "array".into(),
                    offset: 0,
                    size: 3,
                    inner_struct: None,
                },
                FieldOffset {
                    field_name: "bytes_len".into(),
                    offset: 3,
                    size: 2,
                    inner_struct: None,
                },
                FieldOffset {
                    field_name: "bytes".into(),
                    offset: 5,
                    size: 1,
                    inner_struct: None,
                },
                FieldOffset {
                    field_name: "inner_is_present".into(),
                    offset: 6,
                    size: 1,
                    inner_struct: None,
                },
                FieldOffset {
                    field_name: "inner".into(),
                    offset: 7,
                    size: 3,
                    inner_struct: Some(StructOffset {
                        name: "InnerTest",
                        offset: 7,
                        size: 3,
                        fields: vec![
                            FieldOffset {
                                field_name: "num".into(),
                                offset: 7,
                                size: 2,
                                inner_struct: None,
                            },
                            FieldOffset {
                                field_name: "inner".into(),
                                offset: 9,
                                size: 1,
                                inner_struct: Some(StructOffset {
                                    name: "InnerInnerTest",
                                    offset: 9,
                                    size: 1,
                                    fields: vec![FieldOffset {
                                        field_name: "num".into(),
                                        offset: 9,
                                        size: 1,
                                        inner_struct: None,
                                    }],
                                }),
                            },
                        ],
                    }),
                },
                FieldOffset {
                    field_name: "inner2".into(),
                    offset: 10,
                    size: 3,
                    inner_struct: Some(StructOffset {
                        name: "InnerTest",
                        offset: 10,
                        size: 3,
                        fields: vec![
                            FieldOffset {
                                field_name: "num".into(),
                                offset: 10,
                                size: 2,
                                inner_struct: None,
                            },
                            FieldOffset {
                                field_name: "inner".into(),
                                offset: 12,
                                size: 1,
                                inner_struct: Some(StructOffset {
                                    name: "InnerInnerTest",
                                    offset: 12,
                                    size: 1,
                                    fields: vec![FieldOffset {
                                        field_name: "num".into(),
                                        offset: 12,
                                        size: 1,
                                        inner_struct: None,
                                    }],
                                }),
                            },
                        ],
                    }),
                },
            ],
        };

        assert_eq!(offsets.unwrap(), expected_offsets);
    }

    #[test]
    fn test_offsets_option_none() {
        #[derive(Deserialize, Debug, PartialEq, Eq)]
        struct TestInner {
            foo: u32,
        }
        #[derive(Deserialize, Debug, PartialEq, Eq)]
        struct Test {
            inner: Option<TestInner>,
            bar: u8,
        }

        let test = b"\x00\x03";

        let expected = Test {
            inner: None,
            bar: 3,
        };

        let expected_offsets = StructOffset {
            name: "Test".into(),
            offset: 0,
            size: 2,
            fields: vec![
                FieldOffset {
                    field_name: "inner_is_present".into(),
                    offset: 0,
                    size: 1,
                    inner_struct: None,
                },
                FieldOffset {
                    field_name: "bar".into(),
                    offset: 1,
                    size: 1,
                    inner_struct: None,
                },
            ],
        };

        let result = from_bytes_with_offsets::<Test>(test).unwrap();
        assert_eq!(result.0, expected);
        assert_eq!(result.1.unwrap(), expected_offsets);
    }

    #[test]
    fn test_vec_of_struct_roundtrip() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq, Debug)]
        struct Inner {
            foo: u32,
            bar: u8,
        }
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq, Debug)]
        struct Outer {
            items: Vec<Inner>,
        }

        let outer = Outer {
            items: vec![
                Inner { foo: 1, bar: 2 },
                Inner { foo: 3, bar: 4 },
                Inner { foo: 5, bar: 6 },
            ],
        };

        let bytes = crate::binder_serde::to_bytes(&outer).unwrap();
        let parsed = super::from_bytes::<Outer>(&bytes).unwrap();
        assert_eq!(parsed, outer);
    }

    #[test]
    fn test_vec_of_struct_offsets_two_elements() {
        #[derive(Deserialize, PartialEq, Eq, Debug)]
        struct Inner {
            foo: u32,
            bar: u8,
        }
        #[derive(Deserialize, PartialEq, Eq, Debug)]
        struct Outer {
            items: Vec<Inner>,
        }

        // 2 elements: count=2 (u16) + Inner{1,2} (5 bytes) + Inner{3,4} (5 bytes) = 12 bytes.
        let bytes = b"\x02\x00\x01\x00\x00\x00\x02\x03\x00\x00\x00\x04";
        let (parsed, offsets) = from_bytes_with_offsets::<Outer>(bytes).unwrap();
        assert_eq!(
            parsed,
            Outer {
                items: vec![Inner { foo: 1, bar: 2 }, Inner { foo: 3, bar: 4 }],
            }
        );

        let offsets = offsets.unwrap();
        assert_eq!(offsets.name, "Outer");
        assert_eq!(offsets.offset, 0);
        assert_eq!(offsets.size, 12);

        // Layout: items_len pseudo (_len) + items (real, with Inner #0 attached)
        // + items sibling (with Inner #1 attached, reusing the name "items"
        // so dissector lookups still resolve).
        assert_eq!(offsets.fields.len(), 3);

        assert_eq!(offsets.fields[0].field_name, "items_len");
        assert_eq!(offsets.fields[0].offset, 0);
        assert_eq!(offsets.fields[0].size, 2);
        assert!(offsets.fields[0].inner_struct.is_none());

        // Element 0 attaches to the original "items" field.
        assert_eq!(offsets.fields[1].field_name, "items");
        assert_eq!(offsets.fields[1].offset, 2);
        let inner0 = offsets.fields[1]
            .inner_struct
            .as_ref()
            .expect("first element must have inner_struct attached");
        assert_eq!(inner0.name, "Inner");
        assert_eq!(inner0.offset, 2);
        assert_eq!(inner0.size, 5);
        assert_eq!(inner0.fields.len(), 2);
        assert_eq!(inner0.fields[0].field_name, "foo");
        assert_eq!(inner0.fields[1].field_name, "bar");

        // Element 1 lands on a sibling with the same field name as element 0's
        // host so the dissector resolves the same hf/ett registrations.
        assert_eq!(offsets.fields[2].field_name, "items");
        assert_eq!(offsets.fields[2].offset, 7);
        let inner1 = offsets.fields[2]
            .inner_struct
            .as_ref()
            .expect("second element must have inner_struct attached");
        assert_eq!(inner1.name, "Inner");
        assert_eq!(inner1.offset, 7);
        assert_eq!(inner1.size, 5);
    }

    #[test]
    fn test_vec_of_struct_offsets_three_elements() {
        #[derive(Deserialize, PartialEq, Eq, Debug)]
        struct Inner {
            foo: u32,
        }
        #[derive(Deserialize, PartialEq, Eq, Debug)]
        struct Outer {
            items: Vec<Inner>,
        }

        // count=3 (u16) + 3 × u32
        let bytes = b"\x03\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00";
        let (parsed, offsets) = from_bytes_with_offsets::<Outer>(bytes).unwrap();
        assert_eq!(
            parsed,
            Outer {
                items: vec![Inner { foo: 1 }, Inner { foo: 2 }, Inner { foo: 3 }],
            }
        );

        let offsets = offsets.unwrap();
        // _len pseudo + 3 sibling "items" fields, one per element.
        assert_eq!(offsets.fields.len(), 4);
        assert_eq!(offsets.fields[0].field_name, "items_len");
        for i in 1..=3 {
            assert_eq!(offsets.fields[i].field_name, "items");
            let inner = offsets.fields[i]
                .inner_struct
                .as_ref()
                .expect("each element must have inner_struct attached");
            assert_eq!(inner.name, "Inner");
            assert_eq!(inner.fields.len(), 1);
            assert_eq!(inner.fields[0].field_name, "foo");
        }
    }

    #[test]
    fn test_vec_of_struct_offsets_empty() {
        #[derive(Deserialize, PartialEq, Eq, Debug)]
        struct Inner {
            foo: u32,
        }
        #[derive(Deserialize, PartialEq, Eq, Debug)]
        struct Outer {
            items: Vec<Inner>,
        }

        let bytes = b"\x00\x00";
        let (parsed, offsets) = from_bytes_with_offsets::<Outer>(bytes).unwrap();
        assert_eq!(parsed, Outer { items: vec![] });

        let offsets = offsets.unwrap();
        // Empty Vec: just the _len pseudo and the (empty) items field.
        assert_eq!(offsets.fields.len(), 2);
        assert_eq!(offsets.fields[0].field_name, "items_len");
        assert_eq!(offsets.fields[1].field_name, "items");
        assert!(offsets.fields[1].inner_struct.is_none());
    }

    #[test]
    fn test_vec_of_struct_followed_by_field() {
        // Vec<Struct> followed by another field exercises the
        // "next add_field after my synthetic siblings" path — the
        // deserializer's prev_field.size update must not panic on the
        // synthetic sibling.
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq, Debug)]
        struct Inner {
            foo: u32,
        }
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq, Debug)]
        struct Outer {
            items: Vec<Inner>,
            tail: u8,
        }

        let outer = Outer {
            items: vec![Inner { foo: 1 }, Inner { foo: 2 }],
            tail: 0xab,
        };
        let bytes = crate::binder_serde::to_bytes(&outer).unwrap();
        let (parsed, offsets) = from_bytes_with_offsets::<Outer>(&bytes).unwrap();
        assert_eq!(parsed, outer);

        let offsets = offsets.unwrap();
        assert_eq!(offsets.fields.last().unwrap().field_name, "tail");
    }
}
