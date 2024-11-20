# MerkleTree WASM formal specification

Many blockchains such as Ethereum or Polkadot utilize Merkle Trees (or variations like Merkle Patricia Tries) for efficient and secure data verification. This repository contains a WASM implementation of dependency-free Merkle tree algorithms and a formal specification on Inference WASM extension (see [merkle-tree](./merkle-tree.wat) and [specification](./specification.wat)).

---

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

Let us define the following:

- Let $H: \\{0,1\\}^* \rightarrow \\{0,1\\}^{HashSize}$ be a cryptographic hash function.
- Let $S = [h_1, h_2, \ldots, h_n]$ be a sequence of hashes (leaves of the Merkle tree).
- Let $merkleTree(S)$ be a function that constructs a Merkle tree from the sequence $S$ and returns the root hash.
- Let $merkleChain(i,S)$ be the authentication path (chain of proofs) for the $i$-th leaf $h_i$​ in $S$.
- Let $merkleRecon(h,i,c)$ be a function that reconstructs the root hash from a leaf hash $h$, its position $i$ and a chain of proofs $c$.

---

**Property 1: Collision Implication from Identical Root Hashes with Different Leaf Sets**

_Statement:_

There exists an $O(n)$ - complex algorithm that takes two hash sequences $S=[h_1,h_2,…,h_n]$ and $S'=[h_1',h_2', \ldots,h_n']$, producing collision of the hash function $H$, if $S\neq S'$ and Merkle trees constructed from these sequences yield the same root hash. 

_Mathematically:_

There exists $O(n)$ - complex function $F : \\{0,1\\}^{HashSize \times n} \times \\{0,1\\}^{HashSize \times n} \rightarrow \\{0,1\\}^{HashSize \times 2} \times \\{0,1\\}^{HashSize \times 2}$ such that

If $S \neq S'$, $merkleTree(S)=merkleTree(S')$ and $F(S, S') = (x, y)$, then $H(x)=H(y)$.

---

**Property 2: Correctness of Proof Verification for a Valid Leaf**

_Statement:_

For any $i \in \\{1, 2, \ldots, n\\}$, the root hash reconstructed from the $i$-th leaf hash $h_i$​ and its corresponding chain of proofs $merkleChain(i,S)$ equals the root hash of the Merkle tree built from $S$.

_Mathematically:_

For all $i \in \\{1, 2, \ldots, n\\}$ and all $S = [h_1, h_2, \ldots, h_n]$

$\text{merkleRecon}(h_i, i, \text{merkleChain}(i, S)) = \text{merkleTree}(S)$.

---

**Property 3: Collision Implication from Two Leaf Proofs Leading to same Root Hash from same position**

_Statement:_

There exists an $O(\log n)$ - complex algorithm that takes index $i \in \\{1, 2, \ldots, n\\}$, two hashes $h_i \ne h_i'$ and two evidence chains $c, c' \in \\{0,1\\}^{HashSize \times \lceil\log_2 n\rceil}$, producing collision of the hash function $H$, if $\text{merkleRecon}(h_i, i, c) = \text{merkleRecon}(h_i', i, c')$.

_Mathematically:_

There exists $O(\log n)$ - complex function $G : \\{1, 2, \ldots, n\\} \times \\{0,1\\}^{HashSize} \times \\{0,1\\}^{HashSize} \times \\{0,1\\}^{HashSize \times \lceil\log_2 n\rceil} \times \\{0,1\\}^{HashSize \times \lceil\log_2 n\rceil} \rightarrow \\{0,1\\}^{HashSize \times 2} \times \\{0,1\\}^{HashSize \times 2}$ such that

If $\text{merkleRecon}(h, i, c) = \text{merkleRecon}(h', i, c')$ and $G(i, h, h', c, c') = (x, y)$ then $H(x) = H(y)$.

---

**Explanation:**

- **Property 1** ensures that the uniqueness of the root hash depends on the uniqueness of the leaf hashes and the collision resistance of $H$. If different leaf sequences yield the same root, $H$ must have collided somewhere in the tree.
- **Property 2** guarantees that any legitimate leaf can be authenticated against the root hash using its proof chain, maintaining the integrity of the tree structure.
- **Property 3** asserts that if two different leaves can be used to reconstruct the same root hash from the same position with any proof chains, it implies a collision in $H$, violating the tree's integrity.

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

Putting aside the complexity estimation of the solution, for now, let's try to at least formulate its existence.

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
