# MerkleTree WASM formal specification

Many blockchains such as Ethereum or Polkadot utilize Merkle Trees (or variations like Merkle Patricia Tries) for efficient and secure data verification. This repository contains a WASM implementation of dependency-free Merkle tree algorithms and a formal specification on Inference WASM extension (see [merkle-tree](./merkle-tree.wat) and [specification](./specification.wat)).

---

## TOC
- [Pseudocode Implementation](#pseudocode-implementation)
- [Formal Properties of the Merkle Tree Algorithm](#formal-properties-of-the-merkle-tree-algorithm)
  - [Determinism](#1-determinism)
  - [Immutability (Integrity)](#2-immutability-integrity)
  - [Completeness](#3-completeness)
  - [Soundness](#4-soundness)
  - [Efficiency (Computational Complexity)](#5-efficiency-computational-complexity)
  - [Collision Resistance](#6-collision-resistance)
  - [Preimage Resistance](#7-preimage-resistance)
  - [Second Preimage Resistance](#8-second-preimage-resistance)
  - [Proof of Inclusion](#9-proof-of-inclusion)
  - [Uniqueness of Path](#10-uniqueness-of-path)
  - [Non-Malleability](#11-non--malleability)
  - [Data Confidentiality](#12-data-confidentiality)
  - [Stateless Verification](#13-stateless-verification)
  - [Tree Balance Handling](#14-tree-balance-handling)
  - [Inductive Construction](#15-inductive-construction)
- [Rust implementation](#rust-implementation)

### **Pseudocode Implementation**

```pseudo
class MerkleNode:
    left: MerkleNode
    right: MerkleNode
    hash: bytes

function create_merkle_tree(data_blocks):
    nodes = []
    for data in data_blocks:
        nodes.append(MerkleNode(hash=hash_function(data)))

    while len(nodes) > 1:
        temp_nodes = []
        for i in range(0, len(nodes), 2):
            left_node = nodes[i]
            right_node = nodes[i + 1] if i + 1 < len(nodes) else nodes[i]
            combined_hash = hash_function(left_node.hash + right_node.hash)
            parent_node = MerkleNode(left=left_node, right=right_node, hash=combined_hash)
            temp_nodes.append(parent_node)
        nodes = temp_nodes

    return nodes[0]  # Root of the Merkle Tree
```

#### **Explanation**

- **Leaf Nodes**: Created by hashing individual data blocks.
- **Parent Nodes**: Combine hashes of child nodes to create a new hash.
- **Root Node**: The final node represents the root hash, summarizing all underlying data.

### **Formal Properties of the Merkle Tree Algorithm**

#### 1. **Determinism**

- **Definition**: Given the same set of input data blocks, the Merkle Tree algorithm will always produce the same Merkle Root hash.
- **Formal Specification**: $\forall D, \text{MerkleTree}(D) = h$
- **Verification Suitability**: Determinism ensures predictability and consistency, making it possible to formally specify and verify the algorithm's behaviour using mathematical functions.

>[!NOTE]
>This is a non-trivial statement. Formulating the independence of computation from any variables not explicitly passed to the algorithm implies either an explicit enumeration of all possible ways in which the purity of the function can be violated in WASM or the use of non-deterministic references, so we can say, "Whatever computation precedes the algorithm call, if it does not change the input data, it cannot change the output."

#### 2. **Immutability (Integrity)**

- **Definition**: Any change in the input data results in a different Merkle Root hash.
- **Formal Specification**: $\forall D \neq D', \text{MerkleTree}(D) \neq \text{MerkleTree}(D')$
- **Verification Suitability**: Immutability can be formally verified by demonstrating that any alteration in input propagates through hash computations, changing the root hash.

#### 3. **Completeness**

- **Definition**: All input data blocks are included in the tree; none are omitted.
- **Formal Specification**: $\forall d_i \in D, \exists \text{leaf node } n_i \text{ such that } n_i.\text{hash} = h(d_i)$
- **Verification Suitability**: Ensures every data block contributes to the root hash, which can be formally specified and verified.

#### 4. **Soundness**

- **Definition**: If a proof verifies correctly, the data block is indeed part of the Merkle Tree.
- **Formal Specification**: $\text{ValidProof}(d, P, h_{\text{root}}) \implies d \in D$
- **Verification Suitability**: Soundness can be formally specified by showing that only valid proofs correspond to actual data inclusion.

#### 5. **Efficiency (Computational Complexity)**

- **Definitions**:
  - **Construction Time**: Building the tree takes linear time relative to the number of data blocks. $T_{\text{construct}}(n) = O(n)$
  - **Proof Size and Verification Time**: Both are logarithmic relative to the number of data blocks. $\text{ProofSize}(n) = O(\log n), \quad T_{\text{verify}}(n) = O(\log n)$
- **Verification Suitability**: These properties can be formally analyzed using computational complexity theory.

#### 6. **Collision Resistance**

- **Definition**: It's computationally infeasible to find two different data sets that produce the same Merkle Root hash.
- **Formal Specification**:
  $\text{Computationally infeasible to find } D \neq D' \text{ such that } \text{MerkleTree}(D) = \text{MerkleTree}(D')$
- **Verification Suitability**: Based on the collision resistance of the underlying hash function, which can be formally specified and reasoned about.

#### 7. **Preimage Resistance**

- **Definition**: Given a hash output, it's infeasible to find an input that hashes to that output.
- **Formal Specification**: $\text{Given } h, \text{ it's infeasible to find } d \text{ such that } h(d) = h$
- **Verification Suitability**: Ensures that the root hash does not reveal information about the data blocks, suitable for formal cryptographic proofs.

#### 8. **Second Preimage Resistance**

- **Definition**: Given an input and its hash, it's infeasible to find a different input that hashes to the same value.
- **Formal Specification**: $\forall d, \text{ it's infeasible to find } d' \neq d \text{ such that } h(d) = h(d')$
- **Verification Suitability**: Prevents substitution attacks, essential for formal security verification.

#### 9. **Proof of Inclusion**

- **Definition**: Efficiently proving that a data block is part of the Merkle Tree using a Merkle Proof.
- **Formal Specification**: $\text{VerifyProof}(d, P, h_{\text{root}}) = \text{True} \iff d \in D$
- **Verification Suitability**: Formal algorithms can specify and verify the correctness and efficiency of inclusion proofs.

#### 10. **Uniqueness of Path**

- **Definition**: Each leaf node has a unique path to the root.
- **Formal Specification**: $\forall n_{\text{leaf}}, \exists! \text{path } P \text{ such that } \text{PathToRoot}(n_{\text{leaf}}) = P$
- **Verification Suitability**: Ensures that proofs are unambiguous and suitable for formal reasoning about tree structures.

#### 11. **Non-Malleability**

- **Definition**: It's infeasible to alter the tree or a proof without detection.
- **Formal Specification**:$\text{AlteredProof}(P') \implies \text{VerifyProof}(d, P', h_{\text{root}}) = \text{False}$
- **Verification Suitability**: Can be formally specified to ensure that any modification invalidates the proof.

#### 12. **Data Confidentiality**

- **Definition**: The Merkle Root does not reveal information about individual data blocks.
- **Formal Specification**: $\text{Given } h_{\text{root}}, \text{ cannot deduce } d_i$
- **Verification Suitability**: Based on hash function properties, suitable for formal security proofs.

#### 13. **Stateless Verification**

- **Definition**: Verification does not require access to the entire tree or data set.
- **Formal Specification**: $\text{VerifyProof}(d, P, h_{\text{root}}) \text{ uses only } d, P, h_{\text{root}}$
- **Verification Suitability**: Enables lightweight clients, that can be formally specified for verification.

#### 14. **Tree Balance Handling**

- **Definition**: Defines how the tree handles odd numbers of leaf nodes (e.g., duplicating the last node).
- **Formal Specification**:
  - For even $\( n \)$: standard pairing.
  - For odd $\( n \)$: last node paired with itself or as per protocol.
- **Verification Suitability**: Ensures consistent tree structures, can be formally specified.

#### 15. **Inductive Construction**

- **Definition**: The tree can be defined recursively or inductively.
- **Formal Specification**:
  - **Base Case**: For a single leaf node $\( n \)$, $\( h_{\text{root}} = h(n) \)$.
  - **Inductive Step**: For trees $\( T_1 \)$ and $\( T_2 \)$, $\( h_{\text{root}} = h(h_{T_1} || h_{T_2}) \)$.
- **Verification Suitability**: Facilitates formal proofs using mathematical induction.

## Rust implementation

```rust
fn concat_and_hash(l: Hash, r: Hash) -> Hash {
    // hashing implementation
}

fn repeat_and_hash(l: Hash) -> Hash {
    concat_and_hash(l, l)
}

fn merkle_tree(leaves: &[Hash]) -> Vec<Vec<Hash>> {
    let mut tree = vec![leaves.to_vec()];

    loop {
        let layer = tree.last().unwrap();
        let ll = layer.len();
        if ll < 2 {
            break;
        }
        let mut nl = Vec::new();
        for i in (1..ll).step_by(2) {
            nl.push(concat_and_hash(layer[i - 1], layer[i]));
        }
        if ll % 2 != 0 {
            nl.push(repeat_and_hash(layer[ll - 1]));
        }
        tree.push(nl);
    }

    tree
}

fn merkle_root(tree: &[Vec<Hash>]) -> Hash {
    tree.last().unwrap()[0]
}

fn merkle_chain(tree: &[Vec<Hash>], idx: usize) -> Vec<Hash> {
    let mut chain = Vec::new();
    let mut i = idx;

    for layer in &tree[..tree.len() - 1] {
        let i1 = i ^ 1;
        let i2 = if i1 < layer.len() { i1 } else { i };
        chain.push(layer[i2]);
        i >>= 1;
    }

    chain
}

fn merkle_recon(idx: usize, leaf: Hash, chain: &[Hash]) -> Hash {
    let mut acc = leaf;
    let mut i = idx;

    for link in chain {
        acc = if i & 1 != 0 {
            concat_and_hash(*link, acc)
        } else {
            concat_and_hash(acc, *link)
        };
        i >>= 1;
    }

    acc
}
```

The central problem in formulating the properties of cryptographic algorithms is that they are often impossible to express as required by their applications. For example, this:

$$
\forall D \neq D', \text{MerkleTree}(D) \neq \text{MerkleTree}(D')
$$

is clearly false. Collisions inevitably follow from the very principle of hashing, so the best we can formally assert is that finding them is _difficult_. In the case of Merkle trees, the natural benchmark of complexity is the strength of the hash function used, meaning the statement becomes:

> Given a collision of Merkle trees, a collision of the hash function used in their construction can be computed in polynomial time.

Putting aside the complexity estimation of the solution for now, let's try to at least formulate its existence.

```rust
// Auxiliary function that returns two arrays of hashes
// of an undefined but equal length with undefined but
// different contents.
fn data_prep() -> (Vec<Hash>, Vec<Hash>) {
    let size = usize::MAX; // Undefined size
    let data1 = vec![Hash::default(); size];
    let data2 = vec![Hash::default(); size];
    let diff = 0; // Index where data differs
    assert!(data1[diff] != data2[diff]);
    (data1, data2)
}

// INCORRECT!!! To compute hash collisions from collisions of trees,
// we cannot use non-determinism, as complexity can only be adequately
// assessed for classical algorithms. This needs to be rewritten.
fn nondet_collision(tree1: &[Vec<Hash>], tree2: &[Vec<Hash>]) -> ((Hash, Hash), (Hash, Hash)) {
    let i = 0; // Undefined index
    let j = 0; // Undefined index
    assert!(tree1[i][j] == tree2[i][j]);
    let i1 = i - 1;
    let j1 = j << 1;
    let h11 = tree1[i1][j1];
    let h21 = tree2[i1][j1];
    let j2 = j1 + 1;
    let h12 = tree1[i1][j2];
    let h22 = tree2[i1][j2];
    assert!(h11 != h21 || h12 != h22);
    ((h11, h12), (h21, h22))
}

// This is much more correct. Searching for hash collisions in a Merkle
// tree without non-determinism, inspecting each branch of the tree
// no more than once. The thoroughness of such a search convinces,
// provided the reader, looking at this code, can independently conclude
// about its complexity.
fn find_collision(tree1: &[Vec<Hash>], tree2: &[Vec<Hash>]) -> ((Hash, Hash), (Hash, Hash)) {
    let height = tree1.len();
    assert!(height == tree2.len());

    for i in 1..height {
        let width = tree1[i].len();
        assert!(width == tree2[i].len());

        for j in 0..width {
            if tree1[i][j] != tree2[i][j] {
                continue;
            }
            let i1 = i - 1;
            let j1 = j << 1;
            let h11 = tree1[i1][j1];
            let h21 = tree2[i1][j1];
            let j2 = j1 + 1;
            let h12 = tree1[i1][j2];
            let h22 = tree2[i1][j2];

            if h11 != h21 || h12 != h22 {
                return ((h11, h12), (h21, h22));
            }
        }
    }

    panic!("No collision found");
}

fn collision_resistance() {
    let (data1, data2) = data_prep();
    let tree1 = merkle_tree(&data1);
    let tree2 = merkle_tree(&data2);
    assert!(merkle_root(&tree1) == merkle_root(&tree2));

    // Here, for persuasiveness, it would be good to wrap the call
    // to `find_collision` in a construct that at least verifies
    // this is classical computation without undefined values.
    // Even better if this construct limits the computation's complexity
    // to a polynomial relative to the input size.
    let ((h11, h12), (h21, h22)) = find_collision(&tree1, &tree2);

    assert!(h11 != h21 || h12 != h22);
    let h1 = concat_and_hash(h11, h12);
    let h2 = concat_and_hash(h21, h22);
    assert!(h1 == h2);
}

spec {
    total merkle_integrity();
}
```
