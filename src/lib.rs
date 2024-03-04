// #![allow(unused)]
pub const DEBUG: bool = false;

/*  */

use std::collections::*;

/*  */

/* MACROS */
pub trait IsEven
{
    fn is_even(&self) -> bool;
}

pub trait IsOdd
{
    fn is_odd(&self) -> bool;
}

macro_rules! prim_impl
{
    ( $( $t:tt )* ) =>
        {
            $(
                impl IsEven for $t
                    {
                        fn is_even(&self) -> bool
                        {
                            self & 1 == 0
                        }
                    }
                    impl IsOdd for $t
                    {
                        fn is_odd(&self) -> bool
                        {
                            self & 1 != 0
                        }
                    }
            )*
        };
}

prim_impl!(i8 u8 i16 u16 i32 u32 i64 u64 i128 u128 isize usize);

/*  */

#[macro_export]
macro_rules! exit {
	() => { $crate::exit!(1); };
	( $num:expr $(,)? ) => { ::std::process::exit($num); };
	( $num:expr, $fmt:expr $( , $arg:expr )* $(,)? ) => { { eprintln!($fmt $( , $arg )*); $crate::exit!($num); } };
}

/*  */

/* ENUMS */
pub enum Action
{
    Clear,
    Set,
}

pub enum Radix
{
    BIN = 2,
    OCT = 8,
    DEC = 10,
    HEX = 16,
}

/*  */

/* CONSTS */
pub const ASCII_MASK: u8 = 0x20; // Ascii Lowercase Mask
pub const ERR: &str = "Error";
pub const LSB: u16 = 0x00FF; // Less Significant Byte Mask (8-bit)
pub const MSB: u16 = 0xFF00; // Most Significant Byte Mask (8-bit)
pub const LSN: u8 = 0x0F; // Less Significant Nibble Mask (4-bit)
pub const MSN: u8 = 0xF0; // Most Significant Nibble Mask (4-bit)
pub const SIG: u8 = 0x80; // Signed value limit (8-bit)
pub const NULL: u8 = b'\0'; // Null character

/*
pub const BIN_DIGITS: [char; 2] = ['0', '1'];
pub const OCT_DIGITS: [char; 8] = ['0', '1', '2', '3', '4', '5', '6', '7'];
pub const DEC_DIGITS: [char; 10] = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'];
pub const HEX_DIGITS: [char; 22] = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'a', 'b', 'c', 'd', 'e', 'f'];
*/

/*
pub const BIN_DIGITS_: [u8; 2] = [b'0', b'1'];
pub const OCT_DIGITS_: [u8; 8] = [b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7'];
pub const DEC_DIGITS_: [u8; 10] = [b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9'];
pub const HEX_DIGITS_: [u8; 22] = [b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'A', b'B', b'C', b'D', b'E', b'F', b'a', b'b', b'c', b'd', b'e', b'f'];
*/

/*  */

/* SCALING */
pub fn kilo(n: usize) -> usize
{
    n * 1_000
}
pub fn mega(n: usize) -> usize
{
    n * 1_000_000
}
pub fn giga(n: usize) -> usize
{
    n * 1_000_000_000
}
pub fn tera(n: usize) -> usize
{
    n * 1_000_000_000_000
}

pub fn kb(n: usize) -> usize
{
    n << 10 // x1024
}
pub fn mb(n: usize) -> usize
{
    n << 20 // x1048576
}
pub fn gb(n: usize) -> usize
{
    n << 30 // x1073741824
}
pub fn tb(n: usize) -> usize
{
    n << 40 // x1099511627776
}

/*  */

/* PRINTING */
pub fn print_arr<T: std::fmt::Debug>(src: &[T])
{
    src.iter().for_each(|e| println!("{:?}", e));
    println!();
}
pub fn print_vec<T: std::fmt::Debug>(src: &[T])
{
    src.iter().for_each(|e| println!("{:?}", e));
    println!();
}
pub fn print_map<K: std::fmt::Debug, V: std::fmt::Debug>(src: &HashMap<K, V>)
{
    src.iter().for_each(|(k, v)| println!("k:{:?} <> v:{:?}", k, v));
    println!();
}

/*  */

pub fn separated(n: usize) -> String
{
    n.to_string()
        .as_bytes()
        .rchunks(3)
        .rev()
        .map(|byte| unsafe { std::str::from_utf8_unchecked(byte) })
        .collect::<Vec<_>>()
        .join(",")
}
pub fn get_name<F: Fn()>(_: F) -> &'static str
{
    std::any::type_name::<F>()
}
pub fn get_name_short<F: Fn()>(_: F) -> &'static str
{
    std::any::type_name::<F>().rsplit_once(':').unwrap().1
}
/*  */

/* BENCH */
pub fn bench(func: fn(), func_name: &str, times: usize, exprs: usize)
{
    let mut i = times;
    let now = std::time::Instant::now();

    while i > 0
    {
        /* Code Start */

        func();

        /* Code End */
        i -= 1;
    }

    let elapsed = now.elapsed();

    let times = times * exprs;
    let each = elapsed.div_f64(times as f64);

    println!(
        " => [ Executed {:?} {} times in {:.?} ] -> [ Duration: {}ns each ({:?})]",
        func_name,
        separated(times),
        elapsed,
        each.as_nanos(),
        each
    );
}

/*  */

/* STRING CHECKS */
pub fn first_alphabetic_hm_range_l(s: &str) -> bool
{
    let lower = ASCII_MASK | s.as_bytes()[0];
    lower > 0x60 && lower < 0x7B
}

pub fn first_alphabetic_match(s: &str) -> bool
{
    let first = s.as_bytes()[0];

    match ASCII_MASK | first
    {
        0x60 ..= 0x7A => true,
        _ => false,
    }

    // match first {

    //     0x40..=0x5A => true,
    //     0x60..=0x7A => true,
    //     _ => false,
    // }
}

pub fn first_alphabetic_hm_matches_byt(s: &str) -> bool
{
    matches!(ASCII_MASK | s.as_bytes()[0], b'a' ..= b'z')
}

pub fn first_alphabetic_hm_matches_int(s: &str) -> bool
{
    matches!(ASCII_MASK | s.as_bytes()[0], 0x61 ..= 0x7A)
}

pub fn first_alphabetic_cmp(s: &str) -> bool
{
    let first = s.as_bytes()[0];
    let is_upper = first < 0x60;
    let upper = is_upper as u8 * first + !is_upper as u8 * (ASCII_MASK ^ first); // Branchless
    upper > 0x40 && upper < 0x5B
}

pub fn first_alphabetic_hm_range_u(s: &str) -> bool
{
    let first = s.as_bytes()[0];
    let is_lower = first > 0x60;
    // let upper = if is_lower { first } else { ASCII_MASK ^ first }; // If-Else
    let upper = is_lower as u8 * (ASCII_MASK ^ first) + !is_lower as u8 * first; // Branchless
    upper > 0x40 && upper < 0x5B
}

pub fn first_alphabetic_bytes(s: &str) -> bool
{
    (s.as_bytes()[0]).is_ascii_alphabetic()
}

pub fn first_alphabetic_next(s: &str) -> bool
{
    s.bytes().next().unwrap().is_ascii_alphabetic()
}

pub fn first_alphabetic_starts(s: &str) -> bool
{
    s.starts_with(|c: char| c.is_ascii_alphabetic())
}

/*  */

pub fn chr_valid_bin(b: &u8) -> bool
{
    match b
    {
        b'_' | b'0' | b'1' => (),
        _ => return false,
    }
    true
}

pub fn chr_valid_oct(b: &u8) -> bool
{
    match b
    {
        b'_' | b'0' ..= b'7' => (),
        _ => return false,
    }
    true
}

pub fn chr_valid_dec(b: &u8) -> bool
{
    match b
    {
        b'_' | b'0' ..= b'9' => (),
        _ => return false,
    }
    true
}

pub fn chr_valid_hex(b: &u8) -> bool
{
    match b
    {
        b'_' | b'0' ..= b'9' | b'A' ..= b'F' | b'a' ..= b'f' => (),
        _ => return false,
    }
    true
}

pub fn chr_valid_alpha(b: &u8) -> bool
{
    match b
    {
        b'_' | b'A' ..= b'Z' | b'a' ..= b'z' => (),
        _ => return false,
    }
    true
}

pub fn chr_valid_alphanum(b: &u8) -> bool
{
    match b
    {
        b'_' | b'0' ..= b'9' | b'A' ..= b'Z' | b'a' ..= b'z' => (),
        _ => return false,
    }
    true
}

/*  */

pub fn is_alphabetic(s: &str) -> bool
{
    // s.bytes().all(|b: u8| b == b'_' || b.is_ascii_alphabetic())
    for b in s.bytes()
    {
        match b
        {
            b'_' | b'A' ..= b'Z' | b'a' ..= b'z' => (),
            _ => return false,
        }
    }
    true
}

pub fn is_alphanumeric(s: &str) -> bool
{
    // s.bytes().all(|b: u8| b == b'_' || b.is_ascii_alphanumeric())
    for b in s.bytes()
    {
        match b
        {
            b'_' | b'A' ..= b'Z' | b'a' ..= b'z' | b'0' ..= b'9' => (),
            _ => return false,
        }
    }
    true
}

pub fn is_hexadecimal(s: &str) -> bool
{
    // s.bytes().all(|b: u8| b == b'_' || b.is_ascii_hexdigit())
    for byte in s.bytes()
    {
        match byte
        {
            b'_' | b'0' ..= b'9' | b'A' ..= b'F' | b'a' ..= b'f' => (),
            _ => return false,
        }
    }
    true
}

pub fn is_decimal(s: &str) -> bool
{
    // s.bytes().all(|b: u8| b == b'_' || b.is_ascii_digit())
    for byte in s.bytes()
    {
        match byte
        {
            b'_' | b'0' ..= b'9' => (),
            _ => return false,
        }
    }
    true
}

pub fn is_octal_int(s: &str) -> bool
{
    // s.bytes().all(|b: u8| b == b'_' || matches!(b, 0x30..=0x37))
    for byte in s.bytes()
    {
        match byte
        {
            0x5F | 0x30 ..= 0x37 => (),
            _ => return false,
        }
    }
    true
}

pub fn is_octal_byt(s: &str) -> bool
{
    // s.bytes().all(|b: u8| b == b'_' || matches!(b, b'0'..=b'7'))
    for byte in s.bytes()
    {
        match byte
        {
            b'_' | b'0' ..= b'7' => (),
            _ => return false,
        }
    }
    true
}

pub fn is_binary_hm_matches_best(s: &str) -> bool
{
    for byte in s.bytes()
    {
        let valid = matches!(byte, b'_' | b'0' | b'1');
        if !valid
        {
            return false;
        }
    }
    true
}

pub fn is_binary_hm_bool(s: &str) -> bool
{
    for byte in s.bytes()
    {
        let valid = byte == b'_' || byte == b'0' || byte == b'1';
        if !valid
        {
            return false;
        }
    }
    true
}

pub fn is_binary_all(s: &str) -> bool
{
    let test = |b: u8| b == b'_' || b == b'0' || b == b'1';
    s.bytes().all(test)
}

pub fn is_binary_not_any(s: &str) -> bool
{
    // let clos = |b: u8| !(b == b'_' || b == b'0' || b == b'1');
    let test = |b: u8| b != b'_' && b != b'0' && b != b'1';
    !s.bytes().any(test)
}

/*  */

/* STRING CLEAN-UP (Return the String with characters stripped) */
pub fn strip_non_alphanumeric(s: &str) -> String
{
    let test = |c: &char| c.is_alphanumeric();
    s.chars().filter(test).collect()
}

pub fn strip_non_hexadecimal(s: &str) -> String
{
    let test = |c: &char| c.is_ascii_hexdigit();
    s.chars().filter(test).collect()
}

pub fn strip_non_decimal(s: &str) -> String
{
    let test = |c: &char| c.is_ascii_digit();
    s.chars().filter(test).collect()
}

/*  */

/* STRING to HEX STRING CONVERSIONS (Return a 'hex String' from a 'xxx String')  */
pub fn bin2hex(s: &str) -> String
{
    format!("{:X}", u8::from_str_radix(s, 2).unwrap())
}

pub fn oct2hex(s: &str) -> String
{
    format!("{:X}", u8::from_str_radix(s, 8).unwrap())
}

pub fn dec2hex(s: &str) -> String
{
    format!("{:X}", s.parse::<u8>().unwrap())
}

/*  */

/* STRING to UINT CONVERSIONS (Return a 'number' from a 'String') */
pub fn any2usize(s: &str) -> usize
{
    // If the string starts with the '<' or '>' character, only the last, or first byte value are returned.
    // Then this function strip all non-valid characters and identify the Radix from the ASM or C prefixes.
    let (stripped, radix) = if s.starts_with('<')
    {
        (
            s.replace(['<', '$'], "").replace("0x", "").replace('_', "")[2 ..].to_string(),
            16,
        )
    }
    else if s.starts_with('>')
    {
        (
            s.replace(['>', '$'], "").replace("0x", "").replace('_', "")[.. 2].to_string(),
            16,
        )
    }
    else if s.starts_with('$') || s.starts_with("0x")
    {
        (s.replace(['_', '$'], "").replace("0x", ""), 16)
    }
    else if s.starts_with('&') || s.starts_with("0o")
    {
        (s.replace(['_', '&'], "").replace("0o", ""), 8)
    }
    else if s.starts_with('%') || s.starts_with("0b")
    {
        (s.replace(['_', '%'], "").replace("0b", ""), 2)
    }
    else
    {
        (s.replace('_', ""), 10)
    };
    usize::from_str_radix(&stripped, radix).unwrap()
}

/*  */

pub fn hex2u8_from(s: &str) -> u8
{
    u8::from_str_radix(s, 16).unwrap()
}

pub fn hex2u16_from(s: &str) -> u16
{
    u16::from_str_radix(s, 16).unwrap()
}

pub fn hex2u32_from(s: &str) -> u32
{
    u32::from_str_radix(s, 16).unwrap()
}

/*  */

pub fn dec2u8_parse_best(s: &str) -> u8
{
    s.parse::<u8>().unwrap()
}

/*  */

pub fn dec2u16_parse(s: &str) -> u16
{
    s.parse::<u16>().unwrap()
}

/*  */

pub fn bin2u8_from(s: &str) -> u8
{
    u8::from_str_radix(s, 2).unwrap()
}

pub fn oct2u8_from(s: &str) -> u8
{
    u8::from_str_radix(s, 8).unwrap()
}

/*  */

/* UINT to STRING CONVERSIONS (Return a 'String' representing a 'number') */
pub fn u8_to_decimal(n: u8) -> String
{
    format!("{}", n)
}

pub fn u16_to_decimal(n: u16) -> String
{
    format!("{}", n)
}

/*  */

pub fn u8_to_hexadecimal(n: u8) -> String
{
    format!("{:02X}", n)
}

pub fn u16_to_hexadecimal_be(n: u16) -> String
{
    let [hi, lo] = n.to_be_bytes();
    format!("{:02X}", hi) + &format!("{:02X}", lo)
}

/*  */

pub fn struct2dec(src: &[usize]) -> usize
{
    src.iter().fold(0, |acc, elem| acc * 10 + elem)
}

/*  */

/* BYTE MANIP */
pub fn invert_byte(byt: u8) -> u8
{
    !byt
}

pub fn negate_byte(byt: u8) -> u8
{
    byt.wrapping_neg()
}

/*  */

/* BIT MANIP */
pub fn toggle_bool(src: &mut bool)
{
    *src = !*src;
}

pub fn get_nth_bit(n: u8, pos: u8) -> u8
{
    (n >> pos) & 1
}

pub fn get_lowest_bit_match_tz_best(n: u8) -> Option<u32>
{
    match n
    {
        0 => None,
        _ => Some(n.trailing_zeros()),
    }
}

pub fn get_lowest_bit_match_match(n: u8) -> Option<u32>
{
    let mut pos: u32 = 0;
    match n
    {
        0 => None,
        _ =>
        {
            while pos < 8
            {
                match (n >> pos) & 1 != 0
                {
                    true => break,
                    false => pos += 1,
                }
            }
            Some(pos)
        }
    }
}

pub fn get_lowest_bit_match_if(n: u8) -> Option<u32>
{
    let mut pos: u32 = 0;
    match n
    {
        0 => None,
        _ =>
        {
            while pos < 8
            {
                if (n >> pos) & 1 != 0
                {
                    break;
                }
                else
                {
                    pos += 1;
                }
            }
            Some(pos)
        }
    }
}

pub fn sr_bit(src: &mut u8, mask: u8, cond: u8)
{
    // Conditionally set or clear bits in place ; s: source byte ; mask: value (1, 2, 4, 8...) of the manipulated bit ; cond: O=clear, 1=set
    *src = *src ^ (cond.wrapping_neg() ^ *src) & mask;
}

pub fn sr_bit_new(src: u8, mask: u8, cond: u8) -> u8
{
    // Return a byte with conditionally set or clear bits ; s: source byte ; mask: value (1, 2, 4, 8...) of the manipulated bit ; cond: O=clear, 1=set
    src ^ (cond.wrapping_neg() ^ src) & mask
}

/*  */

/* SPLIT BYTES */
pub fn u16_to_le_bytes(n: u16) -> [u8; 2]
{
    // 5
    n.to_le_bytes()
}

pub fn u16_to_le_bytes_hm_(n: u16) -> [u8; 2]
{
    // 6
    // [(s & 0x00FF) as u8, ((s & 0xFF00) >> 8) as u8]
    [n as u8, ((n & 0xFF00) >> 8) as u8]
}

pub fn u16_to_be_bytes(n: u16) -> [u8; 2]
{
    // 5
    n.to_be_bytes()
}

pub fn u16_to_be_bytes_hm_best(n: u16) -> [u8; 2]
{
    // 6
    [((n & 0xFF00) >> 8) as u8, n as u8]
}

/*  */

/* MERGE BYTES */
pub fn u16_from_be_bytes(upper: u8, lower: u8) -> u16
{
    u16::from_be_bytes([upper, lower])
}

pub fn u16_from_be_bytes_hm_best(upper: u8, lower: u8) -> u16
{
    (upper as u16) << 8 | lower as u16
}

pub fn u32_from_be_bytes_hm(upper: u8, up: u8, low: u8, lower: u8) -> u32
{
    (upper as u32) << 24 | (up as u32) << 16 | (low as u32) << 8 | lower as u32
}

/*  */

/* TYPE CONVERSIONS */
// From Bool
pub fn bool_to_u8(src: bool) -> u8
{
    // Match a boolean to 0/1
    src as u8
}

// To Bool
pub fn u8_to_bool(n: u8) -> bool
{
    n != 0
}

pub fn int_to_bool<T: std::cmp::PartialEq<isize>>(n: T) -> bool
{
    n != 0
}

/*  */

// To String
pub fn str_to_string(s: &str) -> String
{
    // From: 'str' to: 'String'
    String::from(s)
}

pub fn bytes_to_string(src: Vec<u8>) -> String
{
    // From: 'Vec<u8>' to: 'String' (from_utf8 consume the vector of bytes)
    String::from_utf8(src).unwrap()
}

pub fn chars_to_string(src: Vec<char>) -> String
{
    // From: 'Vec<char>' to: 'String'
    src.into_iter().collect::<String>()
}

// To Bytes
pub fn str_to_bytes(s: &str) -> Vec<u8>
{
    // From: 'str' to: 'Vec<u8>'
    s.as_bytes().to_vec()
}

pub fn string_to_bytes(s: String) -> Vec<u8>
{
    // From: 'String' to: 'Vec<u8>'
    s.as_bytes().to_vec()
}

pub fn chars_to_bytes(src: Vec<char>) -> Vec<u8>
{
    // From: 'Vec<char>' to: 'Vec<u8>'
    src.iter().map(|c| *c as u8).collect::<Vec<u8>>()
}

/*  */

// To Chars
pub fn str_to_chars(s: &str) -> Vec<char>
{
    // From: 'str' to: 'Vec<char>'
    s.chars().collect::<Vec<char>>()
}

pub fn string_to_chars(s: String) -> Vec<char>
{
    // From: 'String' to: 'Vec<char>'
    s.chars().collect::<Vec<char>>()
}

pub fn bytes_to_chars(src: Vec<u8>) -> Vec<char>
{
    // From: 'Vec<u8>' to: 'Vec<char>'
    src.iter().map(|b| *b as char).collect::<Vec<char>>()
}

/*  */

// To &str ([!]Lifetime[!] Use directly not in a function)
// From: 'String' to: '&str'
// let new_str: &str = &s

// From: 'Vec<u8>' to: '&str'
// let new_str: &str = std::str::from_utf8(&s).expect(ERR)

// From: 'Vec<char>' to: '&str'
// let new_str: &str = &s.iter().collect::<String>()

/*  */

/* FILE UTILS */

pub fn read_to_bytes(path: &str) -> Vec<u8>
{
    std::fs::read(path).unwrap()
}

pub fn read_to_bytes_end(path: &str) -> Vec<u8>
{
    let mut vec: Vec<u8> = Vec::new();
    let _ = std::io::Read::read_to_end(&mut std::fs::File::open(path).unwrap(), &mut vec);
    vec
}

pub fn read_to_string(path: &str) -> String
{
    std::fs::read_to_string(path).unwrap()
}

pub fn read_to_lines(path: &str) -> Vec<String>
{
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(String::from)
        .collect()
}

pub fn read_to_buffer(path: &str) -> std::io::BufReader<std::fs::File>
{
    std::io::BufReader::new((std::fs::File::open(path)).unwrap())
}

/*  */

pub fn write_file(path: String, data: &[u8])
{
    use std::io::Write;
    std::fs::File::create(path).unwrap().write_all(data).unwrap();
}

/*  */

/* MISC. UTILS */
pub fn env_current_dir() -> String
{
    std::env::current_dir().unwrap().display().to_string()
}

/*  */

pub fn generic_add<T: std::ops::Add<Output = T>>(lhs: T, rhs: T) -> T
{
    lhs + rhs
}

/*  */

/*

/* EXPERIMENTS */
pub mod experiments {
    pub fn asm_experiments() {
        // Inline ASM
        // use std::arch::asm::std;
        if std::env::consts::ARCH == "aarch64" {
            use std::arch::asm;
            let mut _x: usize = 4;
            let before_x: usize = _x;
            let _y: usize = 2;
            let before_y: usize = _y;
            unsafe {
                asm!(
                    "add {_x}, {_x}, {_y}",
                    _x = inout(reg) _x,
                    _y = in(reg) _y,
                );
            }
            println!("Test ASM: {} + {} = {}", before_x, before_y, _x);
        } else {
            println!("Not on ARM64 : {}", std::env::consts::ARCH);
        }
    }
}

*/

/*  */

/*

/* MISC. CONSTANTS */
pub const MIN_I8: i8 = i8::MIN;
pub const MIN_I16: i16 = i16::MIN;
pub const MIN_I32: i32 = i32::MIN;
pub const MIN_I64: i64 = i64::MIN;

pub const MAX_I8: i8 = i8::MAX;
pub const MAX_I16: i16 = i16::MAX;
pub const MAX_I32: i32 = i32::MAX;
pub const MAX_I64: i64 = i64::MAX;

pub const MAX_U8: u8 = u8::MAX;
pub const MAX_U16: u16 = u16::MAX;
pub const MAX_U32: u32 = u32::MAX;
pub const MAX_U64: u64 = u64::MAX;

pub const E_F32: f32 = std::f32::consts::E; // 2.7182817 (Euler’s number)

// pub const GOLD_BIG_F32: f32 = std::f32::consts::PHI; // 1.618034 (Golden Ratio)
// pub const GOLD_SMALL_F32: f32 = 1f32 / GOLD_BIG_F32; // 0.618034 (Golden Ratio_)

pub const MACHINE_EPSILON_F32: f32 = std::f32::EPSILON; // 1.1920929e-7
pub const PI_F32: f32 = std::f32::consts::PI; // 3.1415927
pub const TAU_F32: f32 = std::f32::consts::TAU; // 6.2831855 (2*PI)

pub const E_F64: f64 = std::f64::consts::E; // 2.718281828459045 (Euler’s number)

// pub const GOLD_BIG_F64: f64 = std::f64::consts::PHI; // 1.618033988749895 (Golden Ratio)
// pub const GOLD_SMALL_F64: f64 = 1f64 / GOLD_BIG_F64; // 0.6180339887498948 (Golden Ratio_)

pub const MACHINE_EPSILON_F64: f64 = std::f64::EPSILON; // 2.220446049250313e-16
pub const PI_F64: f64 = std::f64::consts::PI; // 3.141592653589793
pub const TAU_F64: f64 = std::f64::consts::TAU; // 6.283185307179586 (2*PI)

// f32 Structs
pub struct Vec2
{
    x: f32,
    y: f32,
}
pub struct Vec3
{
    x: f32,
    y: f32,
    z: f32,
}
pub struct Vec3A
{
    x: f32,
    y: f32,
    z: f32,
}
pub struct Vec4
{
    x: f32,
    y: f32,
    z: f32,
    w: f32,
}
pub struct Quat
{
    x: f32,
    y: f32,
    z: f32,
    w: f32,
}

// f64 Structs
pub struct DVec2
{
    x: f64,
    y: f64,
}
pub struct DVec3
{
    x: f64,
    y: f64,
    z: f64,
}
pub struct DVec4
{
    x: f64,
    y: f64,
    z: f64,
    w: f64,
}
pub struct DQuat
{
    x: f64,
    y: f64,
    z: f64,
    w: f64,
}

// i32 Structs
pub struct IVec2
{
    x: i32,
    y: i32,
}
pub struct IVec3
{
    x: i32,
    y: i32,
    z: i32,
}
pub struct IVec4
{
    x: i32,
    y: i32,
    z: i32,
    w: i32,
}

// i64 Structs
pub struct I64Vec2
{
    x: i64,
    y: i64,
}
pub struct I64Vec3
{
    x: i64,
    y: i64,
    z: i64,
}
pub struct I64Vec4
{
    x: i64,
    y: i64,
    z: i64,
    w: i64,
}

// u32 Structs
pub struct UVec2
{
    x: u32,
    y: u32,
}
pub struct UVec3
{
    x: u32,
    y: u32,
    z: u32,
}
pub struct UVec4
{
    x: u32,
    y: u32,
    z: u32,
    w: u32,
}

// u64 Structs
pub struct U64Vec2
{
    x: u64,
    y: u64,
}
pub struct U64Vec3
{
    x: u64,
    y: u64,
    z: u64,
}
pub struct U64Vec4
{
    x: u64,
    y: u64,
    z: u64,
    w: u64,
}

// bool Structs
pub struct BVec2
{
    x: bool,
    y: bool,
}
pub struct BVec3
{
    x: bool,
    y: bool,
    z: bool,
}
pub struct BVec4
{
    x: bool,
    y: bool,
    z: bool,
    w: bool,
}

// Compound Types
pub struct Mat2
{
    x_axis: Vec2,
    y_axis: Vec2,
}
pub struct DMat2
{
    x_axis: DVec2,
    y_axis: DVec2,
}
pub struct Mat3
{
    x_axis: Vec3,
    y_axis: Vec3,
    z_axis: Vec3,
}
pub struct Mat3A
{
    x_axis: Vec3A,
    y_axis: Vec3A,
    z_axis: Vec3A,
}
pub struct DMat3
{
    x_axis: DVec3,
    y_axis: DVec3,
    z_axis: DVec3,
}
pub struct Mat4
{
    x_axis: Vec4,
    y_axis: Vec4,
    z_axis: Vec4,
    w_axis: Vec4,
}
pub struct DMat4
{
    x_axis: DVec4,
    y_axis: DVec4,
    z_axis: DVec4,
    w_axis: DVec4,
}
pub struct Affine2
{
    matrix2: Mat2,
    translation: Vec2,
}
pub struct DAffine2
{
    matrix2: DMat2,
    translation: DVec2,
}
pub struct Affine3A
{
    matrix3: Mat3A,
    translation: Vec3A,
}
pub struct DAffine3
{
    matrix3: DMat3,
    translation: DVec3,
}

/*  */

pub struct MINMAX
{
    min: f32,
    max: f32,
}

pub struct U64MINMAX
{
    min: u64,
    max: u64,
}

*/

/*  */

/*

mod vectors
{
    use super::*;

    /*  */

    pub fn clamp(x: f32, a: f32, b: f32) -> f32
    {
        x.clamp(a, b)
    }

    pub fn lerp(x: f32, y: f32, s: f32) -> f32
    {
        x + (y - x) * s
    }

    pub fn unlerp(a: f32, b: f32, x: f32) -> f32
    {
        if x <= a
        {
            return 0f32;
        }
        else if x >= b
        {
            return 1f32;
        }
        (x - a) / (b - a)
    }

    pub fn lerp_range(r: MINMAX, t: f32) -> f32
    {
        r.min + (r.max - r.min) * t
    }

    pub fn range(rs_lo: f32, rs_hi: f32, rd_lo: f32, rd_hi: f32, sval: f32) -> f32
    {
        lerp(rd_lo, rd_hi, unlerp(rs_lo, rs_hi, sval))
    }

    /*  */

    // Constructors
    pub fn ivec2(x: i32, y: i32) -> IVec2
    {
        IVec2 { x, y }
    }

    pub fn vec2(x: f32, y: f32) -> Vec2
    {
        Vec2 { x, y }
    }

    pub fn vec3(x: f32, y: f32, z: f32) -> Vec3
    {
        Vec3 { x, y, z }
    }

    pub fn vec4(x: f32, y: f32, z: f32, w: f32) -> Vec4
    {
        Vec4 { x, y, z, w }
    }

    pub fn minmax(min: f32, max: f32) -> MINMAX
    {
        if min < max
        {
            MINMAX { min, max }
        }
        else
        {
            MINMAX { max, min }
        }
    }

    pub fn u64minmax(min: u64, max: u64) -> U64MINMAX
    {
        if min < max
        {
            U64MINMAX { min, max }
        }
        else
        {
            U64MINMAX { max, min }
        }
    }

    /*  */
}

*/

/*  */

#[cfg(test)]
mod tests
{
    // base = 1.8ns
    // 3 cycles per ns @ 3.2Ghz
    // 50_000_000 cycles in 16.67ms => 60fps
    use super::*;

    #[test]
    fn sample_test_()
    {
        fn test_()
        {
            //
        }
        {
            let exprs = 1;
            let times = mega(1);

            let func = test_;
            bench(func, get_name(func), times, exprs);
        }
    }

    #[test]
    fn zero_test()
    {
        assert_eq!(0, 0);
    }

    /*

        #[test]
        fn maths_()
        {
            use vectors::*;

            let min = 10f32;
            let max = 90f32;

            assert_eq!(lerp(min, max, 0.0125f32), 11f32);
            assert_eq!(lerp(min, max, 0.5f32), 50f32);
            assert_eq!(lerp(min, max, 0f32), 10f32);
            assert_eq!(lerp(min, max, 1f32), 90f32);

            assert_eq!(clamp(1f32, min, max), 10f32);
            assert_eq!(clamp(50f32, min, max), 50f32);
            assert_eq!(clamp(99f32, min, max), 90f32);

            assert_eq!(unlerp(min, max, 11f32), 0.0125f32);
            assert_eq!(unlerp(min, max, 50f32), 0.5f32);
            assert_eq!(unlerp(min, max, -25f32), 0f32);
            assert_eq!(unlerp(min, max, 10f32), 0f32);
            assert_eq!(unlerp(min, max, 90f32), 1f32);
            assert_eq!(unlerp(min, max, 125f32), 1f32);

            let dval = range(10f32, 100f32, 2000f32, 20000f32, 50f32);
            assert_eq!(dval, 10000f32);

            let dval = range(10f32, 100f32, 2000f32, 20000f32, 20f32);
            assert_eq!(dval, 4000f32);
        }

    */

    #[test]
    fn struct2dec_()
    {
        assert_eq!(struct2dec(&[1, 0, 2, 4]), 1024);
    }

    #[test]
    fn even_odd_()
    {
        assert!(0u8.is_even());
        assert!(!1usize.is_even());
        assert!(2u32.is_even());
        assert!(!(-1i64).is_even());
        assert!((-2isize).is_even());

        assert!(!0u8.is_odd());
        assert!(1usize.is_odd());
        assert!(!2u32.is_odd());
        assert!((-1i64).is_odd());
        assert!(!(-2isize).is_odd());
    }

    #[test]
    fn string_is_x_()
    {
        {
            assert!(is_alphabetic("Hello"));
            assert!(!is_alphabetic("Hello0"));
        }
        {
            assert!(is_alphanumeric("Hello42"));
            assert!(!is_alphanumeric("Hello-42"));
        }
        {
            assert!(is_hexadecimal("12_34_AB_CD"));
            assert!(!is_hexadecimal("Z1234ABCDF"));
        }
        {
            assert!(is_decimal("1_000"));
            assert!(!is_decimal("Z000"));
        }
    }

    #[test]
    fn any2int_()
    {
        {
            assert_eq!(any2usize("123"), 123);
        }
        {
            assert_eq!(any2usize("&377"), 0xFF);
            assert_eq!(any2usize("0o377"), 0xFF);
        }
        {
            assert_eq!(any2usize("%1111_0000"), 0xF0);
            assert_eq!(any2usize("0b1111_0000"), 0xF0);
        }
        {
            assert_eq!(any2usize("$DEAD"), 0xDEAD);
            assert_eq!(any2usize("0xDEAD"), 0xDEAD);
        }
        {
            assert_eq!(any2usize("<$DE_AD"), 0xAD);
            assert_eq!(any2usize(">$DE_AD"), 0xDE);
        }
        {
            assert_eq!(any2usize("$C0FE_BABE"), 0xC0FE_BABE);
        }
    }

    #[test]
    fn str_x2hex()
    {
        {
            assert_eq!(bin2hex("11110000"), "F0");
            assert_eq!(bin2hex("10101010"), "AA");
        }
        {
            assert_eq!(oct2hex("010"), "8");
            assert_eq!(oct2hex("377"), "FF");
        }
        {
            assert_eq!(dec2hex("10"), "A");
            assert_eq!(dec2hex("255"), "FF");
        }
    }

    #[test]
    fn print_structs()
    {
        if false
        {
            {
                let my_vec_i32 = vec![1, 2, 3, 4, 5];
                println!("Vec:");
                print_vec(&my_vec_i32);
            }
            {
                println!("Vec:");
                let my_vec_str = vec!["apple", "banana", "cherry"];
                print_vec(&my_vec_str);
            }
            {
                println!("Array:");
                let my_arr_i32 = [0x11, 0x22, 0x33, 0x44, 0x55];
                print_arr(&my_arr_i32);
            }
            {
                let mut my_hashmap = HashMap::new();
                my_hashmap.insert("1-one", 1);
                my_hashmap.insert("2-two", 2);
                my_hashmap.insert("3-three", 3);
                println!("HashMap:");
                print_map(&my_hashmap);
            }
            {
                let mut my_hashmap = HashMap::new();
                my_hashmap.insert("A", 'A');
                my_hashmap.insert("B", 'B');
                my_hashmap.insert("C", 'C');
                println!("HashMap:");
                print_map(&my_hashmap);
            }
        }
    }

    #[test]
    fn inv_neg_byte_()
    {
        assert_eq!(invert_byte(0b11110000), 0b00001111);
        assert_eq!(negate_byte(0b11110000), 0b00010000);
    }

    #[test]
    fn scaling()
    {
        assert_eq!(kb(1), 1024);
        assert_eq!(kilo(2), 2000);
    }

    #[test]
    fn bool_convert()
    {
        assert_eq!(bool_to_u8(true), 1);
        assert_eq!(bool_to_u8(false), 0);

        assert!(u8_to_bool(1));
        assert!(!u8_to_bool(0));
        assert!(u8_to_bool(0xFF));

        assert!(!int_to_bool(0));
        assert!(int_to_bool(42));
        assert!(int_to_bool(-69));
    }

    #[test]
    fn int2str()
    {
        assert_eq!(u8_to_decimal(100), "100");
        assert_eq!(u8_to_hexadecimal(100), "64");

        assert_eq!(u16_to_decimal(1000), "1000");
        assert_eq!(u16_to_hexadecimal_be(1000), "03E8");
    }

    #[test]
    fn bit_manip()
    {
        {
            let mut test_bool: bool = true;
            toggle_bool(&mut test_bool);
            assert!(!test_bool);
        }
        {
            assert_eq!(get_nth_bit(0b11111110, 0), 0);
            assert_eq!(get_nth_bit(0b10000000, 7), 1);
        }
        {
            let mut test_byte: u8 = 0b0000_0001;
            test_byte = sr_bit_new(test_byte, 128, 1);
            assert_eq!(test_byte, 0b1000_0001);
            test_byte = sr_bit_new(test_byte, 1, 0);
            assert_eq!(test_byte, 0b1000_0000);
        }
        {
            let mut test_byte: u8 = 0b0000_0001;
            sr_bit(&mut test_byte, 1, 0);
            assert_eq!(test_byte, 0b0000_0000);
            sr_bit(&mut test_byte, 128, 1);
            assert_eq!(test_byte, 0b1000_0000);
        }
    }

    #[test]
    fn str_strip()
    {
        assert_eq!(strip_non_alphanumeric("1234_BABE_XYZ"), "1234BABEXYZ");
        assert_eq!(strip_non_hexadecimal("1234_BABE_XYZ"), "1234BABE");
        assert_eq!(strip_non_decimal("1234_BABE_XYZ"), "1234");
    }

    #[test]
    fn test_neg_()
    {
        fn neg_()
        {
            negate_byte(0x00);
            negate_byte(0x80);
            negate_byte(0xFF);
        }
        {
            let q = 3;
            let n = mega(1);

            let func = neg_;
            bench(func, get_name_short(func), n, q);
        }
    }

    #[test]
    fn bytes_merge_()
    {
        fn u16_to_be_bytes_hm_best_()
        {
            let [hi, lo] = u16_to_be_bytes_hm_best(0x8044);
            assert!(hi == 0x80 && lo == 0x44);
        }
        fn u16_to_be_bytes_()
        {
            let [hi, lo] = u16_to_be_bytes(0x8044);
            assert!(hi == 0x80 && lo == 0x44);
        }
        {
            let q = 1;
            let n = mega(1);

            let func = u16_to_be_bytes_hm_best_;
            bench(func, get_name_short(func), n, q);

            let func = u16_to_be_bytes_;
            bench(func, get_name_short(func), n, q);
        }
    }

    #[test]
    fn bytes_split_()
    {
        fn u16_from_be_bytes_hm_best_()
        {
            assert!(u16_from_be_bytes_hm_best(0x80, 0x44) == 0x8044);
        }
        fn u16_from_be_bytes_()
        {
            assert!(u16_from_be_bytes(0x80, 0x44) == 0x8044);
        }
        {
            let q = 1;
            let n = mega(1);

            let func = u16_from_be_bytes_hm_best_;
            bench(func, get_name_short(func), n, q);

            let func = u16_from_be_bytes_;
            bench(func, get_name_short(func), n, q);
        }
    }

    #[test]
    fn first_alpha_()
    {
        fn first_alphabetic_hm_range_l_()
        {
            assert!(first_alphabetic_hm_range_l("Hello"));
            assert!(first_alphabetic_hm_range_l("hello"));
            assert!(!first_alphabetic_hm_range_l("{Hello"));
            assert!(!first_alphabetic_hm_range_l("0Hello"));
        }
        fn first_alphabetic_match_()
        {
            assert!(first_alphabetic_match("Hello"));
            assert!(first_alphabetic_match("hello"));
            assert!(!first_alphabetic_match("{Hello"));
            assert!(!first_alphabetic_match("0Hello"));
        }
        fn first_alphabetic_hm_matches_byt_()
        {
            assert!(first_alphabetic_hm_matches_byt("Hello"));
            assert!(first_alphabetic_hm_matches_byt("hello"));
            assert!(!first_alphabetic_hm_matches_byt("{Hello"));
            assert!(!first_alphabetic_hm_matches_byt("0Hello"));
        }
        fn first_alphabetic_hm_matches_int_()
        {
            assert!(first_alphabetic_hm_matches_int("Hello"));
            assert!(first_alphabetic_hm_matches_int("hello"));
            assert!(!first_alphabetic_hm_matches_int("{Hello"));
            assert!(!first_alphabetic_hm_matches_int("0Hello"));
        }
        fn first_alphabetic_cmp_()
        {
            assert!(first_alphabetic_cmp("Hello"));
            assert!(first_alphabetic_cmp("hello"));
            assert!(!first_alphabetic_cmp("{Hello"));
            assert!(!first_alphabetic_cmp("0Hello"));
        }
        fn first_alphabetic_hm_range_u_()
        {
            assert!(first_alphabetic_hm_range_u("Hello"));
            assert!(first_alphabetic_hm_range_u("hello"));
            assert!(!first_alphabetic_hm_range_u("{Hello"));
            assert!(!first_alphabetic_hm_range_u("0Hello"));
        }
        fn first_alphabetic_bytes_()
        {
            assert!(first_alphabetic_bytes("Hello"));
            assert!(first_alphabetic_bytes("hello"));
            assert!(!first_alphabetic_bytes("{Hello"));
            assert!(!first_alphabetic_bytes("0Hello"));
        }
        fn first_alphabetic_next_()
        {
            assert!(first_alphabetic_next("Hello"));
            assert!(first_alphabetic_next("hello"));
            assert!(!first_alphabetic_next("{Hello"));
            assert!(!first_alphabetic_next("0Hello"));
        }
        fn first_alphabetic_starts_()
        {
            assert!(first_alphabetic_starts("Hello"));
            assert!(first_alphabetic_starts("hello"));
            assert!(!first_alphabetic_starts("{Hello"));
            assert!(!first_alphabetic_starts("0Hello"));
        }

        {
            let q = 4;
            let n = mega(10);

            let func = first_alphabetic_hm_range_l_;
            bench(func, get_name_short(func), n, q);
            let func = first_alphabetic_match_;
            bench(func, get_name_short(func), n, q);
            let func = first_alphabetic_hm_matches_int_;
            bench(func, get_name_short(func), n, q);
            let func = first_alphabetic_hm_matches_byt_;
            bench(func, get_name_short(func), n, q);

            let func = first_alphabetic_cmp_;
            bench(func, get_name_short(func), n, q);
            let func = first_alphabetic_hm_range_u_;
            bench(func, get_name_short(func), n, q);
            let func = first_alphabetic_bytes_;
            bench(func, get_name_short(func), n, q);
            let func = first_alphabetic_next_;
            bench(func, get_name_short(func), n, q);
            let func = first_alphabetic_starts_;
            bench(func, get_name_short(func), n, q);
        }
    }

    #[test]
    fn all_octal_()
    {
        fn is_octal_int_()
        {
            assert!(is_octal_int("777"));
            assert!(is_octal_int("1_70"));
            assert!(!is_octal_int("1_80"));
        }
        fn is_octal_byt_()
        {
            assert!(is_octal_byt("777"));
            assert!(is_octal_byt("1_70"));
            assert!(!is_octal_byt("1_80"));
        }

        {
            let q = 3;
            let n = mega(1);

            let func = is_octal_int_;
            bench(func, get_name_short(func), n, q);
            let func = is_octal_byt_;
            bench(func, get_name_short(func), n, q);
        }
    }

    #[test]
    fn all_binary_()
    {
        fn is_binary_hm_bool_()
        {
            assert!(is_binary_hm_bool("10_01"));
            assert!(!is_binary_hm_bool("20_00"));
            assert!(!is_binary_hm_bool("10_02"));
        }
        fn is_binary_hm_matches_best_()
        {
            assert!(is_binary_hm_matches_best("10_01"));
            assert!(!is_binary_hm_matches_best("20_00"));
            assert!(!is_binary_hm_matches_best("10_02"));
        }
        fn is_binary_all_()
        {
            assert!(is_binary_all("10_01"));
            assert!(!is_binary_all("20_00"));
            assert!(!is_binary_all("10_02"));
        }
        fn is_binary_not_any_()
        {
            assert!(is_binary_not_any("10_01"));
            assert!(!is_binary_not_any("20_00"));
            assert!(!is_binary_not_any("10_02"));
        }
        {
            let q = 3;
            let n = mega(1);

            let func = is_binary_hm_bool_;
            bench(func, get_name_short(func), n, q);
            let func = is_binary_hm_matches_best_;
            bench(func, get_name_short(func), n, q);
            let func = is_binary_all_;
            bench(func, get_name_short(func), n, q);
            let func = is_binary_not_any_;
            bench(func, get_name_short(func), n, q);
        }
    }

    #[test]
    fn hexstr2int_()
    {
        fn hexstr2int_from_()
        {
            assert_eq!(hex2u8_from("FF"), 0xFF);
            assert_eq!(hex2u16_from("80FF"), 0x80FF);
            assert_eq!(hex2u32_from("10000000"), 0x10_00_00_00);
        }
        {
            let q = 3;
            let n = mega(1);

            let func = hexstr2int_from_;
            bench(func, get_name_short(func), n, q);
        }
    }

    #[test]
    fn decstr2int_()
    {
        fn decstr2u8_parse_best_()
        {
            assert_eq!(dec2u8_parse_best("10"), 0xA);
            assert_eq!(dec2u8_parse_best("128"), 0x80);
        }

        {
            let q = 2;
            let n = mega(1);

            let func = decstr2u8_parse_best_;
            bench(func, get_name_short(func), n, q);
        }
    }

    #[test]
    fn get_low_bit_()
    {
        fn get_lowest_bit_match_tz_best_()
        {
            assert_eq!(get_lowest_bit_match_tz_best(0b0000_0000), None);
            assert_eq!(get_lowest_bit_match_tz_best(0b0000_0001), Some(0));
            assert_eq!(get_lowest_bit_match_tz_best(0b1111_0000), Some(4));
            assert_eq!(get_lowest_bit_match_tz_best(0b1000_0000), Some(7));
        }
        fn get_lowest_bit_match_match_()
        {
            assert_eq!(get_lowest_bit_match_match(0b0000_0000), None);
            assert_eq!(get_lowest_bit_match_match(0b0000_0001), Some(0));
            assert_eq!(get_lowest_bit_match_match(0b1111_0000), Some(4));
            assert_eq!(get_lowest_bit_match_match(0b1000_0000), Some(7));
        }
        fn get_lowest_bit_match_if_()
        {
            assert_eq!(get_lowest_bit_match_if(0b0000_0000), None);
            assert_eq!(get_lowest_bit_match_if(0b0000_0001), Some(0));
            assert_eq!(get_lowest_bit_match_if(0b1111_0000), Some(4));
            assert_eq!(get_lowest_bit_match_if(0b1000_0000), Some(7));
        }
        {
            let q = 4;
            let n = mega(1);

            let func = get_lowest_bit_match_tz_best_;
            bench(func, get_name_short(func), n, q);

            let func = get_lowest_bit_match_match_;
            bench(func, get_name_short(func), n, q);

            let func = get_lowest_bit_match_if_;
            bench(func, get_name_short(func), n, q);
        }
    }
}
