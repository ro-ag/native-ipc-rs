#![cfg_attr(not(feature = "std"), no_std)]
#![doc = "Platform-neutral, pointer-free IPC protocol foundations."]

extern crate alloc;

pub mod codec;
pub mod layout;
pub mod slot;
