pub mod de;
pub mod error;
pub mod ser;

pub use de::{
    from_bytes, from_bytes_with_offsets, read, read_with_offsets, FieldOffset, StructOffset,
};
pub use ser::{to_bytes, write};

#[cfg(test)]
mod test {
    #[derive(serde_repr::Serialize_repr, serde_repr::Deserialize_repr, PartialEq, Eq, Debug)]
    #[repr(u32)]
    enum TestEnum {
        ZERO,
        ONE,
    }

    #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, Eq)]
    struct TestInner {
        en: TestEnum,
    }
    #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, Eq)]
    struct Test {
        int: u32,
        seq: Vec<u8>,
        str: String,
        en: TestEnum,
        inner: TestInner,
        option: Option<u16>,
        array: [u8; 2],
    }

    #[test]
    fn test_se_des() {
        let test = Test {
            int: 0xff,
            seq: vec![3, 2, 1],
            str: "Hello".into(),
            en: TestEnum::ZERO,
            inner: TestInner { en: TestEnum::ONE },
            option: Some(9000),
            array: [1, 2],
        };

        let bytes = super::ser::to_bytes(&test).unwrap();
        let result = super::de::from_bytes::<Test>(&bytes).unwrap();

        assert_eq!(result, test)
    }

    #[test]
    fn test_des_se() {
        let bytes =
            b"\xff\x00\x00\x00\x03\x00\x03\x02\x01\x05\x00Hello\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x02";

        let test = super::de::from_bytes::<Test>(bytes).unwrap();
        let result = super::ser::to_bytes(&test).unwrap();

        assert_eq!(*bytes, *result)
    }
}
