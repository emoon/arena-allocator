[![Build Status](https://github.com/emoon/arena-allocator/workflows/CI/badge.svg)](https://github.com/emoon/arena-allocator/actions?workflow=Rust)
[![Crates.io](https://img.shields.io/crates/v/arena-allocator.svg)](https://crates.io/crates/arena-allocator)
[![Documentation](https://docs.rs/arena-allocator/badge.svg)](https://docs.rs/arena-allocator)

`arena-allocator` is a linear memory allocator for Rust that provides efficient memory management for performance-critical code. The way it's implemented is by reserving a (large) virtual range of memory and then commiting memory as it needs it. 
This means that reserving a large range (several Gigabytes) of memory is cheap, but actually using it will cause the OS to allocate physical memory. 
This is useful for cases where you need to allocate a lot of memory, or don't know how much memory you need.

There are two main uses for this crate:

1. Long-lived memory: If you have allocations that live for the entire lifetime of your program.
2. Temporary memory: If you have a lot of temporary allocations that is only needed during a short period of time. 

## Saftey

This crate should be considered a advanced form of memory management and should be used with caution. 
The crate is designed to be used in performance-critical code and breaks some of the safety guarantees provided by Rust's memory model. 
In particular, the arena-allocator crate allows for the reuse of memory after it has been deallocated, which can lead to use-after-free bugs if not used correctly. 
It is important to understand the implications of using this crate and to follow best practices for memory management to avoid memory leaks and other issues.
In debug mode, the crate provides memory protection to help catch use-after-free bugs by causing crashes when invalid memory is accessed.

See the Understanding rewind section for more information on how to use the rewind function to manage memory in the arena.

## Getting Started

Add the following to your `Cargo.toml`:

```toml
[dependencies]
arena-allocator = "0.1"
```

Example:

```rust
use arena_allocator::{Arena, TypedArena, ArenaError};

fn main() -> Result<(), ArenaError> {
    // Create a new arena with 1 GB bytes of reserved memory.
    let mut arena = Arena::new(1 * 1024 * 1024 * 1024)?;

    // Allocate a single u32 and initialize it to 0.
    let num = arena.alloc_init::<u32>()?;
    *num = 42;

    // Allocate an array of 10 u32s and initialize them to 0.
    let array = arena.alloc_array_init::<u32>(10)?;

    // Rewind the arena, invalidating all previous allocations.
    arena.rewind();

    Ok(())
}
```

## Understanding rewind

The `rewind` function invalidates all previous allocations in the arena, allowing the memory to be reused for new allocations. 
By rewinding the arena, you can quickly recycle memory for new allocations without incurring the cost of deallocating and reallocating memory.
However, it is important to note that rewinding the arena will invalidate all previous allocations, so any references or pointers to memory allocated in the arena will become invalid after calling `rewind`.

Example:

```rust
use arena_allocator::{Arena, TypedArena, ArenaError};

fn main() -> Result<(), ArenaError> {
    // Create a new arena with 1 GB bytes of reserved memory.
    let mut arena = Arena::new(1 * 1024 * 1024 * 1024)?;

    // Allocate a single u32 and initialize it to 0.
    let num = arena.alloc_init::<u32>()?;
    *num = 42;

    arena.rewind();

    *num = 42; // This will cause a crash in debug mode due to memory protection in debug mode.

    Ok(())
}
```
## License

Licensed under either of

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
