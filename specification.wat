(module ;; Merkle tree specification
  (global $hashSize (import "crypto" "hashSize") i32) ;; Output size of hash

  ;; Hashing function. Parameters are:
  ;; 1. The destination address for storing hash results;
  ;; 2. Source address of data to be hashed;
  ;; 3. Size of data to be hashed.
  ;; IMPORTANT: The hashing function must not touch the destination area before
  ;; processing input fully, as these memory ranges may overlap.
  (func $digest (import "crypto" "digest") (param i32 i32 i32))

  ;; Calculation of a Merkle tree height. Takes a number of leaves, returns
  ;; the number of links in the certifying hash chain.
  (func $merkleHeight (import "merkle" "merkleHeight")
    (param i32)
    (result i32)
  )

  ;; Calculation of a Merkle tree weight. Takes a number of leaves, returns
  ;; the total number of nodes in a tree. Memory space for weight times the hash size
  ;; needs to be allocated for tree construction.
  (func $merkleWeight (import "merkle" "merkleWeight")
    (param i32)
    (result i32)
  )

  ;; Construction of Merkle tree. Takes the address of the first leaf and the number of
  ;; leaves. Branching nodes are stored in memory immediately after the last
  ;; leaf, with root hash at the end. Tree weight times hash size need to be
  ;; pre-allocated at the given address to accommodate construction.
  (func $merkleTree (import "merkle" "merkleTree") (param i32 i32))

  ;; Exported helper function to get the address of root hash. Takes the address of a
  ;; tree and number of leaves.
  (func $merkleRoot (import "merkle" "merkleRoot")
    (param i32 i32)
    (result i32)
  )

  ;; Extraction of certifying hash chain for particular leaf. Takes already
  ;; constructed tree with a given number of leaves and index of target leaf.
  (func $merkleChain (import "merkle" "merkleChain")
    (param $chain i32) ;; Destination address for chain serialization
    (param $tree i32) ;; Tree address
    (param $leaves i32) ;; Number of leaves in a tree
    (param $idx i32) ;; Index of leaf to certify
  )

  ;; Reconstruction of tree root using a given certificate. Takes data that was
  ;; hashed into tree leaf at given index and extracted hash chain.
  (func $merkleRecon (import "merkle" "merkleRecon")
    (param $dst i32) ;; Destination address for reconstructed root hash
    (param $idx i32) ;; Index of leaf in question
    (param $data i32) ;; Source address of data hashed into leaf
    (param $len i32) ;; Length of data hashed into leaf
    (param $chain i32) ;; Address of certifying hash chain
    (param $height i32) ;; Height of tree
  )

  (memory (export "mem") 1) ;; Shared memory bank

  ;; Address of pre-allocated temp memory for certificate confirmation.
  ;; Algorithm will use 2 hash slots starting at this address, but only
  ;; while `merkleRecon` runs. It doesn't need to be persisted between calls.
  (global (export "merkleScratchpad") i32)

  ;; Helper function offsetting address of hash from the base over a given number of
  ;; hashes
  (func $addrOf (param $index i32) (param $base i32) (result i32)
    (local.get $index)
      (i32.mul (global.get $hashSize))
      (i32.add (local.get $base))
  )

  ;; We limit the size of the tree with 512 leaves here, but for 256-bit hashes this
  ;; can be safely rized to 2^25 until we exhaust 32-bit address space. Size
  ;; of memory bank needs to be expanded accordingly.
  (global $maxWidth i32 (i32.const 0x200))

  ;; Helper function for `undef`-ining memory ranges
  (func $memoryUndef (param $addr i32) (param $size i32)
    (loop $main_loop
      (if (i32.eqz (local.get $size)) (then return))
      (i32.store8 (local.get $addr) (undef i32))
      (local.set $addr (i32.add (local.get $addr) (i32.const 1)))
      (local.set $size (i32.sub (local.get $size) (i32.const 1)))
      (br $main_loop)
    )
  )

  ;; Deterministic helper function that checks if two memory ranges are
  ;; identical. Returns 1 if there are any discrepancies and 0 otherwise.
  (func $memoryCollate
    (param $addr1 i32)
    (param $addr2 i32)
    (param $size i32)
    (result i32)

    (loop $byte_loop
      (if (i32.eqz (local.get $size)) (then (return (i32.const 0))))

      (i32.ne
        (i32.load8_u (i32.add (local.get $addr1) (local.get $off)))
        (i32.load8_u (i32.add (local.get $addr2) (local.get $off)))
      ) (if (then (return (i32.const 1))))

      (local.set $addr1 (i32.add (local.get $addr1) (i32.const 1)))
      (local.set $addr2 (i32.add (local.get $addr2) (i32.const 1)))
      (local.set $size (i32.sub (local.get $size) (i32.const 1)))
      (br $byte_loop)
    )

    unreachable
  )

  ;; Deterministic helper function that searches for hash collisions in two
  ;; Merkle trees. Returns two addresses of double-hash size blobs.
  (func $findCollision
    (param $tree1 i32)
    (param $tree1 i32)
    (param $width i32)
    (result i32 i32)

    (local $hashSize2 i32)
    (local $skip i32)

    (local.set $hashSize2 (i32.shl (global.get $hashSize) (i32.const 1)))

    (loop $layers_loop
      (local.get $width)
        (i32.lt_u (i32.const 2))
        (if (then unreachable))
      
      (local.get $width)
        (i32.and (i32.const 1))
        (i32.add (local.get $width))
        (local.tee $skip)
        (i32.shr_u (i32.const 1))
        (local.set $width)

      (loop $branches_loop
        (block $branches_block
          (call $memoryCollate
            (local.get $tree1)
            (local.get $tree2)
            (local.get $hashSize2)
          ) (br_if $branches_block i32.eqz)

          (call $memoryCollate
            (call $addrOf (local.get $skip) (local.get $tree1))
            (call $addrOf (local.get $skip) (local.get $tree2))
            (global.get $hashSize)
          ) (br_if $branches_block)

          (return (local.get $tree1) (local.get $tree2))
        )

        (local.set $tree1 (i32.add (local.get $tree1) (local.get $hashSize2)))
        (local.set $tree2 (i32.add (local.get $tree2) (local.get $hashSize2)))
        (local.set $skip (i32.sub (local.get $skip) (i32.const 1)))
        (br_if $branches_loop (i32.gt_u (local.get $skip) (local.get $width)))
      )

      (br $layers_loop)
    )

    unreachable
  )

  ;; Helper procedure that succeeds if there are discrepancies between two
  ;; memory ranges and traps otherwise. Could be written through the reuse of
  ;; `$memoryCollate`, but for didactic purposes we demonstrate idiomatically
  ;; non-deterministic style here.
  (func $memoryDiffer
    (param $addr1 i32)
    (param $addr2 i32)
    (param $size i32)
    (local $off i32)

    (traverse
      (undef i32)
        (local.tee $off)
        (i32.ge_u (local.get $size))
        (if (then unreachable))

      (i32.eq
        (i32.load8_u (i32.add (local.get $addr1) (local.get $off)))
        (i32.load8_u (i32.add (local.get $addr2) (local.get $off)))
      ) (if (then unreachable))
    )
  )

  ;; Helper procedure that succeeds if two memory ranges are identical and
  ;; traps otherwise. Could be written through the reuse of `$memoryCollate`, but
  ;; for didactic purposes, we demonstrate idiomatic non-deterministic style
  ;; here.
  (func $memoryAlike
    (param $addr1 i32)
    (param $addr2 i32)
    (param $size i32)
    (local $off i32)

    (total
      (undef i32)
        (local.tee $off)
        (i32.ge_u (local.get $size))
        (if (then (filter unreachable)))

      (i32.ne
        (i32.load8_u (i32.add (local.get $addr1) (local.get $off)))
        (i32.load8_u (i32.add (local.get $addr2) (local.get $off)))
      ) (if (then unreachable))
    )
  )

  ;; Helper procedure that succeeds if two double-hash size blobs are
  ;; different, but have identical hashes. Uses double-hash size chunks of
  ;; memory starting at address 0 for temp storage. 
  (func $confirmCollision (param $addr1 i32) (param $addr2 i32)
    (local $hashSize2 i32)
    (local.set $hashSize2 (i32.shl (global.get $hashSize) (i32.const 1)))

    (call $memoryDiffer
      (local.get $addr1)
      (local.get $addr2)
      (local.get $hashSize2)
    )

    (call $digest
      (i32.const 0)
      (local.get $addr1)
      (local.get $hashSize2)
    )

    (call $digest
      (global.get $hashSize)
      (local.get $addr2)
      (local.get $hashSize2)
    )

    (call $memoryAlike
      (i32.const 0)
      (global.get $hashSize)
      (global.get $hashSize)
    )
  )

  ;; Main procedure that captures the essence of collision resistance for Merkle
  ;; tree construction. By proving its totality we can confirm that obtaining
  ;; a collision of two Markle trees automatically gives you a hash function
  ;; collision.
  (func $integrity
    (local $width i32)
    (local $weight i32)
    (local $tree1 i32)
    (local $tree2 i32)
    (local $size i32)

    (undef i32)
      (local.tee $width)
      (call $merkleWeight)
      (local.set $weight)

    (filter
      (i32.eqz (local.get $width))
        (if (then unreachable))

      (i32.gt_u (local.get $width) (global.get $maxWidth))
        (if (then unreachable))
    )

    (local.set $tree1 (call $addrOf (i32.const 2) (i32.const 0)))
    (local.set $tree1 (call $addrOf (local.get $weight) (local.get $tree1)))

    (local.set $size (i32.mul (global.get $hashSize) (local.get $width)))

    (call $memoryUndef (local.get $tree1) (local.get $size))
    (call $memoryUndef (local.get $tree2) (local.get $size))

    (filter
      (call $memoryDiffer
        (local.get $tree1)
        (local.get $tree2)
        (local.get $size)
      )
    )

    (call $merkleTree (local.get $tree1) (local.get $width))
    (call $merkleTree (local.get $tree2) (local.get $width))

    (filter
      (call $memoryAlike
        (call $merkleRoot (local.get $tree1) (local.get $width))
        (call $merkleRoot (local.get $tree2) (local.get $width))
        (global.get $hashSize)
      )
    )

    (call $confirmCollision
      (call $findCollision
        (local.get $tree1)
        (local.get $tree2)
        (local.get $width)
      )
    )
  )

  (func $verify
    (total (call $integrity))
  )
)