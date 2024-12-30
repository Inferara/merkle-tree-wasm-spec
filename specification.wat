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

  ;; Helper function offsetting address of hash from the base over a given
  ;; number of hashes.
  (func $addrOf (param $base i32) (param $index i32) (result i32)
    (local.get $index)
      (i32.mul (global.get $hashSize))
      (i32.add (local.get $base))
  )

  ;; We limit the size of the tree with 512 leaves (height 9) here, but for
  ;; 256-bit hashes this can be safely rized to 2^25 (height 25) until we
  ;; exhaust 32-bit address space. Size of memory bank needs to be expanded
  ;; accordingly.
  (global $maxWidth i32 (i32.const 0x200))
  (global $maxHeight i32 (i32.const 9))

  ;; Again, 16К bytes limit on data blobs for hashing is arbitrary, with
  ;; expansion of allocated memory it's safe to raise this to 1G bytes.
  (global $maxDataSize i32 (i32.const 0x4000))

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
  (func $findTreeCollision
    (param $tree1 i32)
    (param $tree1 i32)
    (param $width i32)
    (result i32 i32 i32 i32)

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
            (call $addrOf (local.get $tree1) (local.get $skip))
            (call $addrOf (local.get $tree2) (local.get $skip))
            (global.get $hashSize)
          ) (br_if $branches_block)

          (return
            (local.get $tree1)
            (local.get $hashSize2)
            (local.get $tree2)
            (local.get $hashSize2)
          )
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

    (exists
      (uzumaki i32)
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

    (forall
      (uzumaki i32)
        (local.tee $off)
        (i32.ge_u (local.get $size))
        (if (then (assume unreachable)))

      (i32.ne
        (i32.load8_u (i32.add (local.get $addr1) (local.get $off)))
        (i32.load8_u (i32.add (local.get $addr2) (local.get $off)))
      ) (if (then unreachable))
    )
  )

  ;; Helper procedure that succeeds if two double-hash size blobs are
  ;; different, but have identical hashes. Uses double-hash size chunks of
  ;; memory starting at address 0 for temp storage. 
  (func $confirmCollision
    (param $addr1 i32)
    (param $size1 i32)
    (param $addr2 i32)
    (param $size2 i32)

    ;; (local $hashSize2 i32)
    ;; (local.set $hashSize2 (i32.shl (global.get $hashSize) (i32.const 1)))

    (if (i32.eq (local.get $size1) (local.get $size2))
      (then
        (call $memoryDiffer
          (local.get $addr1)
          (local.get $addr2)
          (local.get $size2)
        )
      )
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

  ;; Main procedure that captures the essence of collision resistance for
  ;; Merkle tree construction. By proving its totality we can confirm that
  ;; obtaining a collision of two Markle trees automatically gives you a hash
  ;; function collision. Take note, that property is restricted to cover only
  ;; trees of the same width (number of leaves), without attempting to provide
  ;; protection against CVE-2012-2459. So indeed, you can extend unbalanced
  ;; Merkle tree with duplicates of its trailing elements in proper order
  ;; without changing its root hash. As a defence against this vulnerability
  ;; you can either avoid unbalanced (non-power-of-two wide) trees, or
  ;; consider tree width intrinsic part if its identity, along with root hash.
  (func $integrity
    (local $width i32)
    (local $weight i32)
    (local $tree1 i32)
    (local $tree2 i32)
    (local $size i32)

    (uzumaki i32)
      (local.tee $width)
      (call $merkleWeight)
      (local.set $weight)

    (assume
      (i32.eqz (local.get $width))
        (if (then unreachable))

      (i32.gt_u (local.get $width) (global.get $maxWidth))
        (if (then unreachable))
    )

    (i32.const 0)
      (call $addrOf (i32.const 2))
      (local.tee $tree1)
      (call $addrOf (local.get $weight))
      (local.set $tree2)

    (local.set $size (i32.mul (global.get $hashSize) (local.get $width)))

    (call $memoryUndef (local.get $tree1) (local.get $size))
    (call $memoryUndef (local.get $tree2) (local.get $size))

    (assume
      (call $memoryDiffer
        (local.get $tree1)
        (local.get $tree2)
        (local.get $size)
      )
    )

    (call $merkleTree (local.get $tree1) (local.get $width))
    (call $merkleTree (local.get $tree2) (local.get $width))

    (assume
      (call $memoryAlike
        (call $merkleRoot (local.get $tree1) (local.get $width))
        (call $merkleRoot (local.get $tree2) (local.get $width))
        (global.get $hashSize)
      )
    )

    (call $confirmCollision
      (call $findTreeCollision
        (local.get $tree1)
        (local.get $tree2)
        (local.get $width)
      )
    )
  )

  ;; Main procedure which totality ensures that evidence built by
  ;; `merkleChain` can be used to confirm inclusion of data block in the
  ;; leaves of Merkle tree. Again, protection against CVE-2012-2459 is your
  ;; own responsibility - for unbalanced trees it is possible to confirm
  ;; repeated inclusion of trailing leaves at indexes beyound real tree width.
  (func $soundness
    (local $width i32)
    (local $height i32)
    (local $weight i32)
    (local $tree i32)
    (local $idx i32)
    (local $chain i32)
    (local $data i32)
    (local $size i32)

    (local.set $width (undef i32))

    (assume
      (i32.eqz (local.get $width))
        (if (then unreachable))

      (i32.gt_u (local.get $width) (global.get $maxWidth))
        (if (then unreachable))
    )

    (local.set $height (call $merkleHeight (local.get $width)))
    (local.set $weight (call $merkleWeight (local.get $width)))

    (i32.const 0)
      (call $addrOf (i32.const 2))
      (local.tee $tree)
      (call $addrOf (local.get $weight))
      (local.tee $chain)
      (call $addrOf (local.get $height))
      (local.set $data)

    (call $memoryUndef
      (local.get $tree)
      (i32.mul (global.get $hashSize) (local.get $width))
    )

    (call $merkleTree (local.get $tree) (local.get $width))

    (uzumaki i32)
      (local.tee $idx)
      (i32.ge_u (local.get $width))
      (if (then (assume unreachable)))

    (call $merkleChain
      (local.get $chain)
      (local.get $tree)
      (local.get $width)
      (local.get $idx)
    )

    (uzumaki i32)
      (local.tee $size)
      (i32.ge_u (global.get $maxDataSize))
      (if (then (assume unreachable)))

    (call $memoryUndef (local.get $data) (local.get $size))

    (call $digest (i32.const 0) (local.get $data) (local.get $size))

    (assume
      (call $memoryAlike
        (call $addrOf (local.get $tree) (local.get $idx))
        (i32.const 0)
        (global.get $hashSize)
      )
    )

    (call $merkleRecon
      (i32.const 0)
      (local.get $idx)
      (local.get $data)
      (local.get $size)
      (local.get $chain)
      (local.get $height)
    )

    (call $memoryAlike
      (call $merkleRoot (local.get $tree) (local.get $width))
      (i32.const 0)
      (global.get $hashSize)
    )
  )

  ;; Main procedure which totality ensures that existence of two different
  ;; datas, for which exist two evidence chains of same height leading to same
  ;; root hash from same position index, implies hash function collision.
  (func $uniqueness
    (local $hashSize2 i32)
    (local $height i32)
    (local $chainsize i32)
    (local $temp1l i32)
    (local $temp1r i32)
    (local $data1 i32)
    (local $datasize1 i32)
    (local $chain1 i32)
    (local $root1 i32)
    (local $temp2l i32)
    (local $temp2r i32)
    (local $data2 i32)
    (local $datasize2 i32)
    (local $chain2 i32)
    (local $root2 i32)
    (local $idx i32)

    (local.set $hashSize2 (i32.shl (global.get $hashSize) (i32.const 1)))

    (uzumaki i32)
      (local.tee $height)
      (i32.gt_u (global.get $maxHeight))
      (if (then (assume unreachable)))

    (i32.mul (local.get $height) (global.get $hashSize))
      (local.set $chainsize)

    (assume
      (uzumaki i32)
        (local.tee $datasize1)
        (i32.gt_u (global.get $maxDataSize))
        (if (then unreachable))

      (uzumaki i32)
        (local.tee $datasize2)
        (i32.gt_u (global.get $maxDataSize))
        (if (then unreachable))
    )

    (i32.const 0)
      (local.tee $temp1l)
      (i32.add (global.get $hashSize))
      (local.tee $temp1r)
      (i32.add (global.get $hashSize))
      (local.tee $data1)
      (i32.add (local.get $datasize1))
      (local.tee $chain1)
      (call $addrOf (local.get $height))
      (local.tee $root1)
      (i32.add (global.get $hashSize))
      (local.tee $temp1l)
      (i32.add (global.get $hashSize))
      (local.tee $temp1r)
      (i32.add (global.get $hashSize))
      (local.tee $data2)
      (i32.add (local.get $datasize2))
      (local.tee $chain2)
      (call $addrOf (local.get $height))
      (local.set $root2)

    (call $memoryUndef (local.get $data1) (local.get $datasize1))
    (call $memoryUndef (local.get $chain1) (local.get $chainsize))
    (call $memoryUndef (local.get $data2) (local.get $datasize2))
    (call $memoryUndef (local.get $chain2) (local.get $chainsize))

    (assume $data_filter
      (i32.ne (local.get $datasize1) (local.get $datasize2))
        (br_if $data_filter)

      (call $memoryDiffer
        (local.get $data1)
        (local.get $data2)
        (local.get $datasize1)
      )

      (uzumaki i32)
        (local.tee $idx)
        (i32.ge_u (i32.shl (i32.const 1) (local.get $height)))
        (if (then unreachable))
    )

    (call $merkleRecon
      (local.get $root1)
      (local.get $idx)
      (local.get $data1)
      (local.get $datasize1)
      (local.get $chain1)
      (local.get $height)
    )

    (call $merkleRecon
      (local.get $root2)
      (local.get $idx)
      (local.get $data2)
      (local.get $datasize2)
      (local.get $chain2)
      (local.get $height)
    )

    (assume
      (call $memoryAlike
        (local.get $root1)
        (local.get $root2)
        (global.get $hashSize)
      )
    )

    (block $height_block
      (loop $height_loop
        (br_if $height_block (i32.eqz (local.get $height)))

        (call $digest
          (local.get $root1)
          (local.get $data1)
          (local.get $datasize1)
        )

        (call $digest
          (local.get $root2)
          (local.get $data2)
          (local.get $datasize2)
        )

        (call $memoryCollate
          (local.get $root1)
          (local.get $root2)
          (global.get $hashSize)
        ) (br_if $height_block i32.eqz)

        (if (i32.and (local.get $idx) (i32.const 1))
          (then
            (memory.copy
              (local.get $temp1l)
              (local.get $chain1)
              (global.get $hashSize)
            )

            (memory.copy
              (local.get $temp1r)
              (local.get $root1)
              (global.get $hashSize)
            )

            (memory.copy
              (local.get $temp2l)
              (local.get $chain2)
              (global.get $hashSize)
            )

            (memory.copy
              (local.get $temp2r)
              (local.get $root2)
              (global.get $hashSize)
            )
          )
          (else
            (memory.copy
              (local.get $temp1l)
              (local.get $root1)
              (global.get $hashSize)
            )

            (memory.copy
              (local.get $temp1r)
              (local.get $chain1)
              (global.get $hashSize)
            )

            (memory.copy
              (local.get $temp2l)
              (local.get $root2)
              (global.get $hashSize)
            )

            (memory.copy
              (local.get $temp2r)
              (local.get $chain2)
              (global.get $hashSize)
            )
          )
        )

        (local.set $height (i32.sub (local.get $height) (i32.const 1)))
        (local.set $data1 (local.get $temp1l))
        (local.set $datasize1 (local.get $hashSize2))
        (local.set $chain1 (call $addrOf (i32.const 1) (local.get $chain1)))
        (local.set $data2 (local.get $temp2l))
        (local.set $datasize2 (local.get $hashSize2))
        (local.set $chain2 (call $addrOf (i32.const 1) (local.get $chain2)))
        (local.set $idx (i32.shr_u (local.get $idx) (i32.const 1)))
        (br $height_loop)
      )
    )

    (call $confirmCollision
      (local.get $data1)
      (local.get $datasize1)
      (local.get $data2)
      (local.get $datasize2)
    )
  )

  (func $verify
    (forall (call $integrity))
    (forall (call $soundness))
    (forall (call $uniqueness))
  )
)
