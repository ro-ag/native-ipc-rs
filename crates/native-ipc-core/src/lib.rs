#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]

extern crate alloc;

pub mod codec;
pub mod layout;
pub mod mapping;
pub mod slot;
