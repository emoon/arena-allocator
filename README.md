# arena-allocator

`arena-allocator` is a memory allocator crate for Rust that provides efficient memory management for temporary or short-lived allocations. It is designed to reduce the overhead and fragmentation associated with frequent small allocations by allocating memory in contiguous blocks. The crate offers a range of features, including rewinding the arena to reuse allocated memory, automatic memory protection in debug mode, and a typed arena for managing memory specific to a single type. 

## Features

* Efficient Memory Management: The arena-allocator crate allocates memory in contiguous blocks, reducing fragmentation and overhead associated with frequent small allocations.
* Rewind Function: The rewind function allows the entire arena to be reset to its initial state, enabling the rapid recycling of memory for temporary allocations.
* Typed Arena: The TypedArena struct provides a type-specific arena for managing memory allocated to a single type, simplifying memory management and reducing the risk of errors.
* Memory Protection: In debug mode, the arena-allocator crate protects the memory of invalidated objects, helping to catch use-after-free bugs by causing crashes when invalid memory is accessed.
* Error Handling: The crate provides a custom ArenaError type to handle allocation errors, making it easier to manage memory allocation failures in Rust programs.

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
    // Create a new arena with 1024 bytes of reserved memory.
    let mut arena = Arena::new(1024)?;

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

The `rewind` function invalidates all previous allocations in the arena, allowing the memory to be reused for new allocations. This can be useful for managing temporary memory in performance-critical code, where frequent allocations and deallocations can lead to memory fragmentation and overhead. By rewinding the arena, you can quickly recycle memory for new allocations without incurring the cost of deallocating and reallocating memory.


