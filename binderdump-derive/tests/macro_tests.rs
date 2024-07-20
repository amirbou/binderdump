#![allow(dead_code)]

use binderdump_derive::{ConstOffsets, EpanProtocol, EpanProtocolEnum};
use binderdump_trait::{
    ConstOffsets, EpanProtocol, EpanProtocolEnum, FieldDisplay, FieldInfo, FieldOffset, FtEnum,
    StringMapping, StringMapping64, StringsMap, StructOffset,
};
use pretty_assertions::assert_eq;

#[derive(EpanProtocolEnum)]
#[repr(u32)]
enum TestEnum {
    ONE = 1,
    TWO = 2,
}

#[test]
fn test_derive() {
    #[derive(EpanProtocol)]
    struct InnerTest {
        field1: u32,
    }

    #[derive(EpanProtocol)]
    #[epan(name = "test")]
    struct Test {
        #[epan(name = "foo", abbrev = "bar", ftype = Protocol, display = SepSpace)]
        field1: u32,
        field2: u8,
        field3: Vec<u8>,
        field4: Vec<i32>,
        field5: Option<i64>,
        field6: Option<Vec<u8>>,
        field7: TestEnum,
        field8: Option<TestEnum>,
        field9: Vec<TestEnum>,
        field10: InnerTest,
    }

    let expected = vec![
        FieldInfo {
            name: "foo".into(),
            abbrev: "test.bar".into(),
            ftype: FtEnum::Protocol,
            display: FieldDisplay::SepSpace,
            strings: None,
        },
        FieldInfo {
            name: "field2".into(),
            abbrev: "test.field2".into(),
            ftype: FtEnum::U8,
            display: FieldDisplay::Hex,
            strings: None,
        },
        FieldInfo {
            name: "field3 length".into(),
            abbrev: "test.field3_len".into(),
            ftype: FtEnum::U16,
            display: FieldDisplay::HexDec,
            strings: None,
        },
        FieldInfo {
            name: "field3".into(),
            abbrev: "test.field3".into(),
            ftype: FtEnum::Bytes,
            display: FieldDisplay::SepSpace,
            strings: None,
        },
        FieldInfo {
            name: "field4 length".into(),
            abbrev: "test.field4_len".into(),
            ftype: FtEnum::U16,
            display: FieldDisplay::HexDec,
            strings: None,
        },
        FieldInfo {
            name: "field4".into(),
            abbrev: "test.field4".into(),
            ftype: FtEnum::I32,
            display: FieldDisplay::Dec,
            strings: None,
        },
        FieldInfo {
            name: "field5 is present?".into(),
            abbrev: "test.field5_is_present".into(),
            ftype: FtEnum::Boolean,
            display: FieldDisplay::None,
            strings: None,
        },
        FieldInfo {
            name: "field5".into(),
            abbrev: "test.field5".into(),
            ftype: FtEnum::I64,
            display: FieldDisplay::Dec,
            strings: None,
        },
        FieldInfo {
            name: "field6 is present?".into(),
            abbrev: "test.field6_is_present".into(),
            ftype: FtEnum::Boolean,
            display: FieldDisplay::None,
            strings: None,
        },
        FieldInfo {
            name: "field6 length".into(),
            abbrev: "test.field6_len".into(),
            ftype: FtEnum::U16,
            display: FieldDisplay::HexDec,
            strings: None,
        },
        FieldInfo {
            name: "field6".into(),
            abbrev: "test.field6".into(),
            ftype: FtEnum::Bytes,
            display: FieldDisplay::SepSpace,
            strings: None,
        },
        FieldInfo {
            name: "field7".into(),
            abbrev: "test.field7".into(),
            ftype: FtEnum::U32,
            display: FieldDisplay::Dec,
            strings: Some(StringsMap::U32(vec![
                StringMapping {
                    value: 1,
                    string: c"ONE",
                },
                StringMapping {
                    value: 2,
                    string: c"TWO",
                },
            ])),
        },
        FieldInfo {
            name: "field8 is present?".into(),
            abbrev: "test.field8_is_present".into(),
            ftype: FtEnum::Boolean,
            display: FieldDisplay::None,
            strings: None,
        },
        FieldInfo {
            name: "field8".into(),
            abbrev: "test.field8".into(),
            ftype: FtEnum::U32,
            display: FieldDisplay::Dec,
            strings: Some(StringsMap::U32(vec![
                StringMapping {
                    value: 1,
                    string: c"ONE",
                },
                StringMapping {
                    value: 2,
                    string: c"TWO",
                },
            ])),
        },
        FieldInfo {
            name: "field9 length".into(),
            abbrev: "test.field9_len".into(),
            ftype: FtEnum::U16,
            display: FieldDisplay::HexDec,
            strings: None,
        },
        FieldInfo {
            name: "field9".into(),
            abbrev: "test.field9".into(),
            ftype: FtEnum::U32,
            display: FieldDisplay::Dec,
            strings: Some(StringsMap::U32(vec![
                StringMapping {
                    value: 1,
                    string: c"ONE",
                },
                StringMapping {
                    value: 2,
                    string: c"TWO",
                },
            ])),
        },
        FieldInfo {
            name: "field1".into(),
            abbrev: "test.field10.field1".into(),
            ftype: FtEnum::U32,
            display: FieldDisplay::Dec,
            strings: None,
        },
    ];

    assert_eq!(
        Test::get_info("Test".into(), "test".into(), None, None),
        expected
    );

    assert_eq!(
        Test::get_subtrees("test".into()),
        vec!["test".to_string(), "test.field10".to_string()]
    );
}

#[test]
fn test_array() {
    #[derive(EpanProtocol)]
    struct Test {
        bytes: [u8; 10],
        ints: [u32; 2],
    }

    let expected = vec![
        FieldInfo {
            name: "bytes".into(),
            abbrev: "test.bytes".into(),
            ftype: FtEnum::Bytes,
            display: FieldDisplay::SepSpace,
            strings: None,
        },
        FieldInfo {
            name: "ints".into(),
            abbrev: "test.ints".into(),
            ftype: FtEnum::U32,
            display: FieldDisplay::Dec,
            strings: None,
        },
    ];

    assert_eq!(
        Test::get_info("Test".into(), "test".into(), None, None),
        expected
    );
    assert_eq!(Test::get_subtrees("test".into()), vec!["test".to_string()]);
}

#[test]
fn test_enum() {
    let expected = StringsMap::U32(vec![
        StringMapping {
            value: 1,
            string: c"ONE",
        },
        StringMapping {
            value: 2,
            string: c"TWO",
        },
    ]);

    assert_eq!(TestEnum::get_strings_map(), expected);
    assert_eq!(TestEnum::get_repr(), FtEnum::U32);
    assert_eq!(TestEnum::get_subtrees("test".into()), Vec::<String>::new());
    assert_eq!(TestEnum::ONE.to_cstr(), c"ONE");
    assert_eq!(TestEnum::TWO.to_cstr(), c"TWO");
    assert_eq!(TestEnum::ONE.to_str(), "ONE");
    assert_eq!(TestEnum::TWO.to_str(), "TWO");
}

#[test]
fn test_enum64() {
    #[derive(EpanProtocolEnum)]
    #[repr(u64)]
    enum Test {
        ONE = 1,
        TWO = 2,
    }

    let expected = StringsMap::U64(vec![
        StringMapping64 {
            value: 1,
            string: c"ONE",
        },
        StringMapping64 {
            value: 2,
            string: c"TWO",
        },
    ]);

    assert_eq!(Test::get_strings_map(), expected);
    assert_eq!(Test::get_repr(), FtEnum::U64);
    assert_eq!(Test::get_subtrees("test".into()), Vec::<String>::new());
}

#[test]
fn test_inner_structs() {
    #[derive(EpanProtocol)]
    struct Test {
        foo: u16,
        inner_option: Option<TestInner>,
        inner: TestInner,
        en: TestEnum,
    }

    #[derive(EpanProtocol)]
    struct TestInner {
        bar: u32,
        inner: Vec<TestInnerInner>,
    }

    #[derive(EpanProtocol)]
    struct TestInnerInner {
        baz: u64,
    }

    #[derive(EpanProtocolEnum)]
    #[repr(u64)]
    enum TestEnum {
        ONE = 1,
        TWO = 2,
    }

    let expected = vec![
        FieldInfo {
            name: "foo".into(),
            abbrev: "test.foo".into(),
            ftype: FtEnum::U16,
            display: FieldDisplay::Dec,
            strings: None,
        },
        FieldInfo {
            name: "inner_option is present?".into(),
            abbrev: "test.inner_option_is_present".into(),
            ftype: FtEnum::Boolean,
            display: FieldDisplay::None,
            strings: None,
        },
        FieldInfo {
            name: "bar".into(),
            abbrev: "test.inner_option.bar".into(),
            ftype: FtEnum::U32,
            display: FieldDisplay::Dec,
            strings: None,
        },
        FieldInfo {
            name: "inner length".into(),
            abbrev: "test.inner_option.inner_len".into(),
            ftype: FtEnum::U16,
            display: FieldDisplay::HexDec,
            strings: None,
        },
        FieldInfo {
            name: "baz".into(),
            abbrev: "test.inner_option.inner.baz".into(),
            ftype: FtEnum::U64,
            display: FieldDisplay::Dec,
            strings: None,
        },
        FieldInfo {
            name: "bar".into(),
            abbrev: "test.inner.bar".into(),
            ftype: FtEnum::U32,
            display: FieldDisplay::Dec,
            strings: None,
        },
        FieldInfo {
            name: "inner length".into(),
            abbrev: "test.inner.inner_len".into(),
            ftype: FtEnum::U16,
            display: FieldDisplay::HexDec,
            strings: None,
        },
        FieldInfo {
            name: "baz".into(),
            abbrev: "test.inner.inner.baz".into(),
            ftype: FtEnum::U64,
            display: FieldDisplay::Dec,
            strings: None,
        },
        FieldInfo {
            name: "en".into(),
            abbrev: "test.en".into(),
            ftype: FtEnum::U64,
            display: FieldDisplay::Dec,
            strings: Some(StringsMap::U64(vec![
                StringMapping64 {
                    value: 1,
                    string: c"ONE",
                },
                StringMapping64 {
                    value: 2,
                    string: c"TWO",
                },
            ])),
        },
    ];

    let expected_subtrees: Vec<String> = vec![
        "test".into(),
        "test.inner_option".into(),
        "test.inner_option.inner".into(),
        "test.inner".into(),
        "test.inner.inner".into(),
    ];

    assert_eq!(
        Test::get_info("Test".into(), "test".into(), None, None),
        expected
    );
    assert_eq!(Test::get_subtrees("test".into()), expected_subtrees);
}

#[test]
fn test_const_offsets() {
    #[derive(ConstOffsets)]
    #[repr(C, packed)]
    struct InnerInnerTest {
        num: u8,
    }

    #[derive(ConstOffsets)]
    #[repr(C, packed)]
    struct InnerTest {
        num: i16,
        inner: InnerInnerTest,
    }
    #[derive(ConstOffsets)]
    #[repr(C, packed)]
    struct Test {
        array: [u8; 3],
        inner: InnerTest,
    }

    let expected_offsets = StructOffset {
        name: "Test",
        offset: 0,
        size: 6,
        fields: vec![
            FieldOffset {
                field_name: "array".into(),
                offset: 0,
                size: 3,
                inner_struct: None,
            },
            FieldOffset {
                field_name: "inner".into(),
                offset: 3,
                size: 3,
                inner_struct: Some(StructOffset {
                    name: "InnerTest",
                    offset: 3,
                    size: 3,
                    fields: vec![
                        FieldOffset {
                            field_name: "num".into(),
                            offset: 3,
                            size: 2,
                            inner_struct: None,
                        },
                        FieldOffset {
                            field_name: "inner".into(),
                            offset: 5,
                            size: 1,
                            inner_struct: Some(StructOffset {
                                name: "InnerInnerTest",
                                offset: 5,
                                size: 1,
                                fields: vec![FieldOffset {
                                    field_name: "num".into(),
                                    offset: 5,
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

    let offsets = Test::get_offsets(0);

    assert_eq!(offsets.unwrap(), expected_offsets)
}
