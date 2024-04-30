The document explores the approach, implementation details, results, and analysis of a block construction program developed . The program follows the fundamental Bitcoin protocol for tasks like transaction selection, validation etc. 

### Approach
-The program implements it functionalities in a well defined manner:

1.Selecting the transaction

-Transactions are read from the mempool directory and validated based on supported scriptPubKey types
-Selects transactions within block weight limit and maximizes total fees.

2. Validation of Transaction:
-Function creates a sighash or preimage to check a signatures validity.

3. Constructing Coinbase Transaction:
-In the coinbase transaction it incorporates block reward and witness commitment which links the coinbase transaction to the block via Merkle root

4. Calculating Merkle Root :
-Pairwise hashing of transactions recursively results in a single root hash, providing integrity guarantees within a block.

5. Creating Block Header :

-The block header fields are populated with the following: version, previous hash, Merkle root, timestamp, target difficulty.
-Iterates over nonces through a loop until a valid hash meeting the target difficulty is found.


After the above steps the Block header, coinbase transaction, and transaction IDs are serialized into a standardized, transmissible format and are put in file.

### Details
- block_maker: Organizes the block creation process and writes block data to a file.
- read_transactions: Reads JSON files and parses mempool transactions.
- transaction_selector: Iterates through transactions, performs validation checks,  and implements fee-based transaction selection logic meeting weight limits and maximizing fees.
- create_block_header: Constructs the header, including mining functionality until a valid hash is found.
- create_coinbase: Generates the coinbase transaction 
- create_merkle_root: Uses the Merkle tree algorithm to implement the Merkle tree construction.


### Validating Transaction

- validate_legacy*: For legacy transactions, validates signatures with public keys.
- validate_segwit: For SegWit transactions, validates signatures or falls back to legacy validation.
- verify_signature: Utilizes ECDSA signature verification with secp256k1 library

### Serialization of Blocks

- serialize_block_header: Serializes the taken block header components through little-endian byte streams ordering
- serialize_transaction: Serializes transaction components, handles data depending on for regular and SegWit transactions.
- serialize_witness: Serializes witness data by encoding the number of elements into byte streams.

The program is able to create valid block structures according to above design.

##Conclusion

This provided me in-depth insights into the complexities of block creation through the Bitcoin protocol.
