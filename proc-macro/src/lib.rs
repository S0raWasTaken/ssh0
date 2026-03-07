use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, parse_macro_input};

/// Derives a `from_byte` method for `#[repr(u8)]` enums, allowing
/// conversion from a single byte to an enum variant.
///
/// # Requirements
/// - The enum must be `#[repr(u8)]`
/// - All variants must be unit variants (no fields)
///
/// # Example
/// ```rust
/// #[derive(FromByte)]
/// #[repr(u8)]
/// pub enum SshMessage {
///     Input = 0x00,
///     Resize = 0x01,
/// }
///
/// assert_eq!(SshMessage::from_byte([0x00]), Some(SshMessage::Input));
/// assert_eq!(SshMessage::from_byte([0xFF]), None);
/// ```
#[proc_macro_derive(FromByte)]
pub fn derive_from_byte(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let variants = match &input.data {
        Data::Enum(e) => &e.variants,
        _ => {
            return quote! {
                compile_error!("FromByte can only be derived for enums");
            }
            .into();
        }
    };

    let arms = variants.iter().map(|v| {
        let ident = &v.ident;
        quote! {
            x if x == #name::#ident as u8 => Some(#name::#ident),
        }
    });

    quote! {
        impl #name {
            pub fn from_byte(byte: [u8; 1]) -> Option<Self> {
                match byte[0] {
                    #(#arms)*
                    _ => None,
                }
            }
        }
    }
    .into()
}

/// Derives a `to_byte` method for `#[repr(u8)]` enums, converting
/// a variant to its single-byte representation.
///
/// # Requirements
/// - The enum must be `#[repr(u8)]`
/// - All variants must be unit variants (no fields)
///
/// # Example
/// ```rust
/// #[derive(ToByte)]
/// #[repr(u8)]
/// pub enum SshMessage {
///     Input = 0x00,
///     Resize = 0x01,
/// }
///
/// assert_eq!(SshMessage::Input.to_byte(), [0x00]);
/// ```
///
/// # Errors
/// Does not panic. Emits a compile error if applied to anything other than an enum.
#[proc_macro_derive(ToByte)]
pub fn derive_to_byte(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    match &input.data {
        Data::Enum(_) => {}
        _ => {
            return quote! {
                compile_error!("ToByte can only be derived for enums");
            }
            .into();
        }
    }

    quote! {
        impl #name {
            pub fn to_byte(self) -> [u8; 1] {
                [self as u8]
            }
        }
    }
    .into()
}
