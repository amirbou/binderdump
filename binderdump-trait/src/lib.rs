use std::ffi::CStr;

#[derive(Debug, PartialEq, Eq)]
pub enum FtEnum {
    // used for text labels with no value
    None,
    Protocol,
    // TRUE and FALSE come from <glib.h>
    Boolean,
    // 1-octet character as 0-255
    Char,
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    AbsoulteTime,
    RelativeTime,
    // counted string, with no null terminator
    String,
    // null-terminated string
    StringZ,
    Ether,
    Bytes,
    IPv4,
    IPv6,
    // a UINT32, but if selected lets you go to frame with that number
    FrameNum,
    // GUID, UUID
    Guid,
}

impl TryFrom<&str> for FtEnum {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "None" => Ok(FtEnum::None),
            "Protocol" => Ok(FtEnum::Protocol),
            "Boolean" => Ok(FtEnum::Boolean),
            "Char" => Ok(FtEnum::Char),
            "u8" | "U8" => Ok(FtEnum::U8),
            "u16" | "U16" => Ok(FtEnum::U16),
            "u32" | "U32" => Ok(FtEnum::U32),
            "i8" | "I8" => Ok(FtEnum::I8),
            "i16" | "I16" => Ok(FtEnum::I16),
            "i32" | "I32" => Ok(FtEnum::I32),
            "u64" | "usize" | "U64" => Ok(FtEnum::U64),
            "i64" | "isize" | "I64" => Ok(FtEnum::I64),
            "AbsoluteTime" => Ok(FtEnum::AbsoulteTime),
            "RelativeTime" => Ok(FtEnum::RelativeTime),
            "String" => Ok(FtEnum::String),
            "StringZ" => Ok(FtEnum::StringZ),
            "Ether" => Ok(FtEnum::Ether),
            "Bytes" => Ok(FtEnum::Bytes),
            "IPv4" => Ok(FtEnum::IPv4),
            "IPv6" => Ok(FtEnum::IPv6),
            "FrameNum" => Ok(FtEnum::FrameNum),
            "Guid" => Ok(FtEnum::Guid),
            _ => Err(format!("Unsupported FtEnum type: {}", value)),
        }
    }
}

impl From<FtEnum> for &'static str {
    fn from(value: FtEnum) -> Self {
        match value {
            FtEnum::None => "None",
            FtEnum::Protocol => "Protocol",
            FtEnum::Boolean => "Boolean",
            FtEnum::Char => "Char",
            FtEnum::U8 => "U8",
            FtEnum::U16 => "U16",
            FtEnum::U32 => "U32",
            FtEnum::U64 => "U64",
            FtEnum::I8 => "I8",
            FtEnum::I16 => "I16",
            FtEnum::I32 => "I32",
            FtEnum::I64 => "I64",
            FtEnum::AbsoulteTime => "AbsoluteTime",
            FtEnum::RelativeTime => "RelativeTime",
            FtEnum::String => "String",
            FtEnum::StringZ => "StringZ",
            FtEnum::Ether => "Ether",
            FtEnum::Bytes => "Bytes",
            FtEnum::IPv4 => "IPv4",
            FtEnum::IPv6 => "IPv6",
            FtEnum::FrameNum => "FrameNum",
            FtEnum::Guid => "Guid",
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub enum FieldDisplay {
    // Integral types
    // none
    #[default]
    None,
    // decimal
    Dec,
    // hexadecimal
    Hex,
    // octal
    Oct,
    // decimal (hexadecimal)
    DecHex,
    // hexadecimal (decimal)
    HexDec,

    // call custom routine (in ->strings) to format
    Custom,

    // String types
    // shows non-printable ASCII characters as C-style escapes
    StrAsciis,
    // shows non-printable UNICODE characters as \\uXXXX (XXX for now non-printable characters display depends on UI)
    StrUnicode,

    // Byte separators
    // hexadecimal bytes with a period (.) between each byte
    SepDot,
    // hexadecimal bytes with a dash (-) between each byte
    SepDash,
    // hexadecimal bytes with a colon (:) between each byte
    SepColon,
    // hexadecimal bytes with a space between each byte
    SepSpace,
}

#[derive(Debug, PartialEq, Eq)]
pub struct StringMapping {
    pub value: u32,
    pub string: &'static CStr,
}

#[derive(Debug, PartialEq, Eq)]
pub struct StringMapping64 {
    pub value: u64,
    pub string: &'static CStr,
}

#[derive(Debug, PartialEq, Eq)]
pub enum StringsMap {
    U32(Vec<StringMapping>),
    U64(Vec<StringMapping64>),
}

#[derive(Debug, PartialEq, Eq)]
pub struct FieldInfo {
    pub name: String,
    pub abbrev: String,
    pub ftype: FtEnum,
    pub display: FieldDisplay,
    pub strings: Option<StringsMap>,
}

pub trait EpanProtocolEnum {
    fn get_strings_map() -> StringsMap;
    fn get_repr() -> FtEnum;
}

pub trait EpanProtocol {
    // flag to specify if a specific T: EpanProtocol should be interpreted as `FtEnum::Bytes` for `Vec<T>`
    const IS_BYTES_VECTOR: bool = false;
    fn get_info(
        name: String,
        abbrev: String,
        ftype: Option<FtEnum>,
        display: Option<FieldDisplay>,
    ) -> Vec<FieldInfo>;

    fn get_subtrees(abbrev: String) -> Vec<String> {
        vec![abbrev]
    }
}

macro_rules! impl_epan_primitive {
    ($ty:ty, $ft:ident, $fd:ident, $is_bytes:expr) => {
        impl EpanProtocol for $ty {
            const IS_BYTES_VECTOR: bool = $is_bytes;
            fn get_info(
                name: String,
                abbrev: String,
                ftype: Option<FtEnum>,
                display: Option<FieldDisplay>,
            ) -> Vec<FieldInfo> {
                vec![FieldInfo {
                    name,
                    abbrev,
                    ftype: ftype.unwrap_or(FtEnum::$ft),
                    display: display.unwrap_or(FieldDisplay::$fd),
                    strings: None,
                }]
            }

            fn get_subtrees(_abbrev: String) -> Vec<String> {
                vec![]
            }
        }
    };
    ($ty:ty, $ft:ident, $fd:ident) => {
        impl_epan_primitive!($ty, $ft, $fd, false);
    };
}

impl_epan_primitive!(i8, I8, Hex, true);
impl_epan_primitive!(i16, I16, Dec);
impl_epan_primitive!(i32, I32, Dec);
impl_epan_primitive!(i64, I64, Dec);
impl_epan_primitive!(isize, I64, Dec);
impl_epan_primitive!(u8, U8, Hex, true);
impl_epan_primitive!(u16, U16, Dec);
impl_epan_primitive!(u32, U32, Dec);
impl_epan_primitive!(u64, U64, Dec);
impl_epan_primitive!(usize, U64, Dec);
impl_epan_primitive!(bool, Boolean, None);

impl<T: EpanProtocol> EpanProtocol for Vec<T> {
    fn get_info(
        name: String,
        abbrev: String,
        ftype: Option<FtEnum>,
        display: Option<FieldDisplay>,
    ) -> Vec<FieldInfo> {
        let mut length_name = name.clone();
        let mut length_abbrev = abbrev.clone();

        length_name.push_str(" length");
        length_abbrev.push_str("_len");
        let mut info = vec![FieldInfo {
            name: length_name,
            abbrev: length_abbrev,
            ftype: FtEnum::U16,
            display: FieldDisplay::HexDec,
            strings: None,
        }];

        let mut field_info = T::get_info(name, abbrev, None, None);
        if T::IS_BYTES_VECTOR || ftype.is_some() || display.is_some() {
            let last_field = field_info.last_mut().unwrap();
            last_field.ftype = ftype.unwrap_or(FtEnum::Bytes);
            last_field.display = display.unwrap_or(FieldDisplay::SepSpace);
        }

        info.append(&mut field_info);
        info
    }

    fn get_subtrees(abbrev: String) -> Vec<String> {
        T::get_subtrees(abbrev)
    }
}

impl<T: EpanProtocol, const N: usize> EpanProtocol for [T; N] {
    fn get_info(
        name: String,
        abbrev: String,
        ftype: Option<FtEnum>,
        display: Option<FieldDisplay>,
    ) -> Vec<FieldInfo> {
        let mut field_info = T::get_info(name, abbrev, None, None);
        if T::IS_BYTES_VECTOR || ftype.is_some() || display.is_some() {
            let last_field = field_info.last_mut().unwrap();
            last_field.ftype = ftype.unwrap_or(FtEnum::Bytes);
            last_field.display = display.unwrap_or(FieldDisplay::SepSpace);
        }

        field_info
    }

    fn get_subtrees(abbrev: String) -> Vec<String> {
        T::get_subtrees(abbrev)
    }
}

impl<T: EpanProtocol> EpanProtocol for Option<T> {
    fn get_info(
        name: String,
        abbrev: String,
        ftype: Option<FtEnum>,
        display: Option<FieldDisplay>,
    ) -> Vec<FieldInfo> {
        let mut is_present_name = name.clone();
        let mut is_present_abbrev = abbrev.clone();
        is_present_name.push_str(" is present?");
        is_present_abbrev.push_str("_is_present");

        let mut info = vec![FieldInfo {
            name: is_present_name,
            abbrev: is_present_abbrev,
            ftype: FtEnum::Boolean,
            display: FieldDisplay::None,
            strings: None,
        }];

        let mut field_info = T::get_info(name, abbrev, ftype, display);
        info.append(&mut field_info);
        info
    }

    fn get_subtrees(abbrev: String) -> Vec<String> {
        T::get_subtrees(abbrev)
    }
}

impl<T: EpanProtocolEnum> EpanProtocol for T {
    fn get_info(
        name: String,
        abbrev: String,
        ftype: Option<FtEnum>,
        display: Option<FieldDisplay>,
    ) -> Vec<FieldInfo> {
        let strings = Some(T::get_strings_map());
        let default_ftype = T::get_repr();

        vec![FieldInfo {
            name,
            abbrev,
            ftype: ftype.unwrap_or(default_ftype),
            display: display.unwrap_or(FieldDisplay::Dec),
            strings,
        }]
    }

    fn get_subtrees(_abbrev: String) -> Vec<String> {
        vec![]
    }
}
