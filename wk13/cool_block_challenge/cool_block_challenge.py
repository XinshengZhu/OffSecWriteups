from pwn import *

URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1512
NETID = b"xz4344"

p = remote(URL, PORT)
p.recvuntil(b"NetID (something like abc123): ")
p.sendline(NETID)

# Extract the IV (Initialization Vector) from the server response
p.recvuntil(b"IV = ")
iv_hex_string = p.recvline().strip().decode()
iv = bytes.fromhex(iv_hex_string)   # Convert IV from hex string to bytes

# Extract the ciphertext from the server response
p.recvuntil(b"Ciphertext = ")
ciphertext_hex_string = p.recvline().strip().decode()
ciphertext = bytes.fromhex(ciphertext_hex_string)   # Convert ciphertext from hex string to bytes

log.info("Start padding oracle attack...")

# Initialize variables for the attack
plaintext = b"" # Stores the recovered plaintext
block_size = 16 # AES block size in bytes

# Split the ciphertext into blocks, prepending the IV as the first block
blocks = [iv] + [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
total_blocks = len(blocks) - 1  # Total number of ciphertext blocks (excluding IV)
total_bytes = total_blocks * block_size # Total bytes to decrypt

# Process each ciphertext block in reverse order (last block to first block)
for block_index in range(len(blocks) - 1, 0, -1):
    current_block = blocks[block_index] # Current ciphertext block
    previous_block = blocks[block_index - 1]    # Previous ciphertext block (used in CBC decryption)
    recovered_block = bytearray(block_size) # Placeholder for the decrypted plaintext block

    # Recover each byte of the plaintext block (starting from the last byte)
    for padding_length in range(1, block_size + 1):
        padding_start_byte_index = block_size - padding_length  # Position of the byte being recovered
        modified_previous_block = bytearray(previous_block) # Create a mutable copy of the previous block

        # Adjust bytes in the modified previous block to satisfy the padding condition for known bytes
        for byte_index in range(padding_start_byte_index + 1, block_size):
            modified_previous_block[byte_index] = previous_block[byte_index] ^ recovered_block[byte_index] ^ padding_length

        # Guess the current byte of the plaintext by iterating over all possible values (0-255)
        for guess_byte in range(256):
            # Modify the target byte in the previous block to test the guess: c_n ^ s ^ X_(n-1) = c_n ^ s ^ c_(n-1) ^ m_n ^ pad = m_n ^ m_n ^ pad = pad
            modified_previous_block[padding_start_byte_index] = previous_block[padding_start_byte_index] ^ guess_byte ^ padding_length
            # Construct the payload: modified previous block + current block
            payload = b"".join([bytes(modified_previous_block), current_block]).hex()
            # Send the payload to the server
            p.recvuntil(b"!\n")
            p.sendline(payload.encode())

            # Receive and parse the server response
            line = p.recvline().strip().decode()
            if ":)" in line:    # Padding is valid
                log.info(f"Guessing the {padding_start_byte_index + 1}/{block_size} byte of the {block_index}/{total_blocks} block: {hex(guess_byte)}")
                # Record the correctly guessed byte
                recovered_block[padding_start_byte_index] = guess_byte
                break

    # Log the recovered plaintext block
    log.info(f"Recovering the {block_index}/{total_blocks} block: {bytes(recovered_block)}")
    # Prepend the recovered block to the plaintext (blocks are processed in reverse order)
    plaintext = bytes(recovered_block) + plaintext

# Remove PKCS#7 padding from the decrypted plaintext
padding_value = plaintext[-1]
if 1 <= padding_value <= block_size and all(padding_byte == padding_value for padding_byte in plaintext[-padding_value:]):
    plaintext = plaintext[:-padding_value]

log.info("Complete padding oracle attack!")

# Output the decrypted plaintext in both hex and ASCII formats
log.info(f"Decrypting plaintext in hex: {plaintext.hex()}")
log.info(f"Decrypting plaintext in ASCII: {plaintext.decode()}")

# Title: Don Quixote

# Author: Miguel de Cervantes Saavedra

# Translator: John Ormsby

# CHAPTER VIII.
# OF THE GOOD FORTUNE WHICH THE VALIANT DON QUIXOTE HAD IN THE TERRIBLE
# AND UNDREAMT-OF ADVENTURE OF THE WINDMILLS, WITH OTHER OCCURRENCES
# WORTHY TO BE FITLY RECORDED

# At this point they came in sight of thirty or forty windmills that
# there are on that plain, and as soon as Don Quixote saw them he said to
# his squire, "Fortune is arranging matters for us better than we could
# have shaped our desires ourselves, for look there, friend Sancho Panza,
# where thirty or more monstrous giants present themselves, all of whom I
# mean to engage in battle and slay, and with whose spoils we shall begin
# to make our fortunes; for this is righteous warfare, and it is God's
# good service to sweep so evil a breed from off the face of the earth."

# "What giants?" said Sancho Panza.

# "Those thou seest there," answered his master, "with the long arms, and
# some have them nearly two leagues long."

# "Look, your worship," said Sancho; "what we see there are not giants
# but windmills, and what seem to be their arms are the sails that turned
# by the wind make the millstone go."

# "It is easy to see," replied Don Quixote, "that thou art not used to
# this business of adventures; those are giants; and if thou art afraid,
# flag{F1gh71ng_g14n75_w1th__p4dding_4774ck5!_1580a3e1f12316dc}
# away with thee out of this and betake thyself to prayer while I engage
# them in fierce and unequal combat."

# So saying, he gave the spur to his steed Rocinante, heedless of the
# cries his squire Sancho sent after him, warning him that most certainly
# they were windmills and not giants he was going to attack. He, however,
# was so positive they were giants that he neither heard the cries of
# Sancho, nor perceived, near as he was, what they were, but made at them
# shouting, "Fly not, cowards and vile beings, for a single knight
# attacks you."

# A slight breeze at this moment sprang up, and the great sails began to
# move, seeing which Don Quixote exclaimed, "Though ye flourish more arms
# than the giant Briareus, ye have to reckon with me."

# So saying, and commending himself with all his heart to his lady
# Dulcinea, imploring her to support him in such a peril, with lance in
# rest and covered by his buckler, he charged at Rocinante's fullest
# gallop and fell upon the first mill that stood in front of him; but as
# he drove his lance-point into the sail the wind whirled it round with
# such force that it shivered the lance to pieces, sweeping with it horse
# and rider, who went rolling over on the plain, in a sorry condition.
# Sancho hastened to his assistance as fast as his ass could go, and when
# he came up found him unable to move, with such a shock had Rocinante
# fallen with him.

# "God bless me!" said Sancho, "did I not tell your worship to mind what
# you were about, for they were only windmills? and no one could have
# made any mistake about it but one who had something of the same kind in
# his head."

# flag{F1gh71ng_g14n75_w1th__p4dding_4774ck5!_1580a3e1f12316dc}
