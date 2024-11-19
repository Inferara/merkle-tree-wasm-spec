(module ;; Self-contained Merkle tree implementation
  (memory (import "env" "mem") 1) ;; External memory bank
  (global $hashSize (import "crypto" "hashSize") i32) ;; Output size of the hash

  ;; Hashing function. Parameters are:
  ;; 1. The destination address for storing hash results;
  ;; 2. Source address of data to be hashed;
  ;; 3. Size of data to be hashed.
  ;; IMPORTANT: The hashing function must not touch the destination area before
  ;; processing input fully, as these memory ranges may overlap.
  (func $digest (import "crypto" "digest") (param i32 i32 i32))

  ;; Address of pre-allocated temp memory for certificate confirmation.
  ;; Algorithm will use 2 hash slots starting at this address, but only
  ;; while `merkleRecon` runs. It doesn't need to be persisted between calls.
  (global $temp (import "env" "merkleScratchpad") i32)

  ;; Calculation of a Merkle tree height. Takes a number of leaves, returns
  ;; the number of links in the certifying hash chain.
  (func $height (export "merkleHeight") (param $leaves i32) (result i32)
    (local $result i32) ;; Accumulated return value

    ;; Number of leaves must not be 0
    (if (i32.eqz (local.get $leaves)) (then unreachable))

    (loop $height_loop ;; Main loop
      ;; For a singular leaf return accumulated height
      (if (i32.lt_u (local.get $leaves) (i32.const 2))
        (then (return (local.get $result)))
      )

      ;; Increment height
      (local.get $result)
        (i32.add (i32.const 1))
        (local.set $result)

      ;; Halve number of leaves
      (local.get $leaves)
        (i32.shr_u (i32.const 1))
        (local.set $leaves)

      ;; Repeat
      (br $height_loop)
    )

    ;; Needed to suppress implicit typing error
    unreachable
  )

  ;; Calculation of a Merkle tree weight. Takes a number of leaves, returns
  ;; the total number of nodes in a tree. Memory space for weight times the hash size
  ;; needs to be allocated for tree construction.
  (func $weight (export "merkleWeight") (param $leaves i32) (result i32)
    (local $result i32) ;; Accumulated return value

    ;; If a number of leaves is less than 2, return it
    (if (i32.lt_u (local.get $leaves) (i32.const 2))
      (then (return (local.get $leaves)))
    )

    (loop $layers_loop ;; Main loop
      ;; If a number of leaves is odd, increment it by 1 and add to the accumulator
      (local.get $leaves)
        (i32.and (i32.const 1))
        (i32.add (local.get $leaves))
        (local.tee $leaves)
        (i32.add (local.get $result))
        (local.set $result)

      ;; Halve the number of leaves and, if it is more than 1, repeat
      (local.get $leaves)
        (i32.shr_u (i32.const 1))
        (local.tee $leaves)
        (i32.gt_u (i32.const 1))
        (br_if $layers_loop)
    )

    ;; Return accumulated result with additional slot for tree root
    (return (i32.add (local.get $result) (local.get $leaves)))
  )

  ;; Helper function offsetting address of hash from the base over a given number of
  ;; hashes
  (func $addrOf (param $index i32) (param $base i32) (result i32)
    (local.get $index)
      (i32.mul (global.get $hashSize))
      (i32.add (local.get $base))
  )

  ;; Construction of Merkle tree. Takes the address of the first leaf and the number of
  ;; leaves. Branching nodes are stored in memory immediately after the last
  ;; leaf, with root hash at the end. Tree weight times hash size need to be
  ;; pre-allocated at the given address to accommodate construction.
  (func (export "merkleTree") (param $addr i32) (param $count i32)
    (local $hashSize2 i32) ;; Doubled hash size for shortcutting calculations
    (local $prev i32) ;; Address of the previous layer to take lower branches from
    (local $i i32) ;; Index of the current branch in a layer under construction

    ;; Pre-calculating doubled hash size
    (local.set $hashSize2 (i32.shl (global.get $hashSize) (i32.const 1)))

    (loop $layer_loop ;; Outter loop for layer processing
      ;; If the current layer consists of 0 or 1 hashes, we are done
      (if (i32.lt_u (local.get $count) (i32.const 2)) (then return))

      (block $odd_block ;; Processing layers with an odd number of hashes
        ;; If a number of hashes isn't odd, skip
        (local.get $count)
          (i32.and (i32.const 1))
          (i32.eqz)
          (br_if $odd_block)

        ;; Duplication of last hash in layer
        (memory.copy
          (call $addrOf
            (local.get $count)
            (local.get $addr)
          )

          (call $addrOf
            (i32.sub (local.get $count) (i32.const 1))
            (local.get $addr)
          )

          (global.get $hashSize)
        )

        ;; Incrementing layer size by 1
        (local.set $count (i32.add (local.get $count) (i32.const 1)))
      )

      ;; Current layer becomes the previous layer of new iteration
      (local.set $prev (local.get $addr))
      ;; Next layer starts immediately after current
      (local.set $addr (call $addrOf (local.get $count) (local.get $addr)))
      ;; Next layer is half the size of the current
      (local.set $count (i32.shr_u (local.get $count) (i32.const 1)))
      ;; Reset branch index to zero
      (local.set $i (i32.const 0))

      (loop $branch_loop ;; Inner loop over branches in the same layer
        ;; Hashing sequential pair of hashes in the previous layer into current
        (call $digest
          (call $addrOf
            (local.get $i)
            (local.get $addr)
          )

          (call $addrOf
            (i32.shl (local.get $i) (i32.const 1))
            (local.get $prev)
          )

          (local.get $hashSize2)
        )

        ;; Incrementing branch index and looping back if the layer is not finished
        (local.get $i)
          (i32.add (i32.const 1))
          (local.tee $i)
          (i32.lt_u (local.get $count))
          (br_if $branch_loop)
      )

      ;; Loop back into processing next layer
      (br $layer_loop)
    )
  )

  ;; Exported helper function to get the address of root hash. Takes the address of a
  ;; tree and number of leaves.
  (func (export "merkleRoot")
    (param $addr i32)
    (param $count i32)
    (result i32)

    (local.get $count)
      (call $weight)
      (i32.sub (i32.const 1))
      (call $addrOf (local.get $addr))
  )

  ;; Extraction of certifying hash chain for particular leaf. Takes already
  ;; constructed tree with a given number of leaves and index of target leaf.
  (func (export "merkleChain")
    (param $chain i32) ;; Destination address for chain serialization
    (param $tree i32) ;; Tree address
    (param $leaves i32) ;; Number of leaves in a tree
    (param $idx i32) ;; Index of leaf to certify

    ;; We can not certify leaf with index out of range
    (if (i32.ge_u (local.get $idx) (local.get $leaves)) (then unreachable))

    (loop $chain_loop ;; Main loop
      ;; If a current layer has a singular node, we are done
      (if (i32.lt_u (local.get $leaves) (i32.const 2)) (then return))

      ;; Round up the number of nodes in the current layer to be even
      (local.get $leaves)
        (i32.and (i32.const 1))
        (i32.add (local.get $leaves))
        (local.set $leaves)

      ;; Copy hash paired with current index to the destination address
      (memory.copy
        (local.get $chain)

        (call $addrOf
          (i32.xor (local.get $idx) (i32.const 1))
          (local.get $tree)
        )

        (global.get $hashSize)
      )

      ;; Slide to next destination address
      (local.get $chain)
        (i32.add (global.get $hashSize))
        (local.set $chain)

      ;; Slide to the next layer of a tree
      (local.get $tree)
        (call $addrOf (local.get $leaves))
        (local.set $tree)

      ;; Halve down a number of nodes in layer
      (local.get $leaves)
        (i32.shr_u (i32.const 1))
        (local.set $leaves)

      ;; Halve down the index of the node to certify
      (local.get $idx)
        (i32.shr_u (i32.const 1))
        (local.set $idx)

      ;; Loop back to the next iteration
      (br $chain_loop)
    )
  )

  ;; Reconstruction of tree root using the given certificate. Takes data that was
  ;; hashed into tree leaf at given index and extracted hash chain.
  (func (export "merkleRecon")
    (param $dst i32) ;; Destination address for reconstructed root hash
    (param $idx i32) ;; Index of leaf in question
    (param $data i32) ;; Source address of data hashed into leaf
    (param $len i32) ;; Length of data hashed into leaf
    (param $chain i32) ;; Address of certifying hash chain
    (param $height i32) ;; Height of tree

    (local $hashSize2 i32) ;; Doubled hash size for shortcutting calculations
    (local $second i32) ;; Address of second hash slot in temp memory

    ;; Pre-calculating doubled hash size
    (local.set $hashSize2 (i32.shl (global.get $hashSize) (i32.const 1)))
    ;; Pre-calculating address of second hash slot of temp memory
    (local.set $second (i32.add (global.get $temp) (global.get $hashSize)))

    (block $recon_block ;; Outter block for preemptive loop termination
      (loop $recon_loop ;; Main inner loop
        ;; Terminating when the chain is exhausted
        (local.get $height)
          (i32.eqz)
          (br_if $recon_block)

        ;; Filling temp memory with a pair of hashes for the next iteration. One is
        ;; hashed from the result of the previous iteration, another is copied from
        ;; current chain link. The order of pairing is decided by the evenness of
        ;; current index.
        (if (i32.and (local.get $idx) (i32.const 1))
          (then
            (call $digest
              (local.get $second)
              (local.get $data)
              (local.get $len)
            )

            (memory.copy
              (global.get $temp)
              (local.get $chain)
              (global.get $hashSize)
            )
          )
          (else
            (call $digest
              (global.get $temp)
              (local.get $data)
              (local.get $len)
            )

            (memory.copy
              (local.get $second)
              (local.get $chain)
              (global.get $hashSize)
            )
          )
        )

        ;; Halving index for next iteration
        (local.set $idx (i32.shr_u (local.get $idx) (i32.const 1)))
        ;; Next data to hash is always in temp memory
        (local.set $data (global.get $temp))
        ;; Next length of data to hash is always 2 hash sizes
        (local.set $len (local.get $hashSize2))
        ;; Sliding to the next chain link
        (local.set $chain (i32.add (local.get $chain) (global.get $hashSize)))
        ;; Reducing the number of remaining links by 1
        (local.set $height (i32.sub (local.get $height) (i32.const 1)))
        ;; Looping back to the next iteration
        (br $recon_loop)
      )
    )

    ;; Finalizing root hash reconstruction from the result of last iteration
    (call $digest (local.get $dst) (local.get $data) (local.get $len))
  )
)
