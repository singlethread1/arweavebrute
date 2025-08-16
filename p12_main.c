///////////////////////////////////////////////////////////////////////////////////////
//              P U Z Z L E # 12
//         \/  \/  \/
//These are taken directly from a base64 to hex of the encrypted message
//This is for puzzle #12. Change these values to work with other puzzles.
///////////////////////////////////////////////////////////////////////////////////////
//8 byte salt - the 8 bytes that follow the "Salted__" prefix
const char ciphersalt[8] = {
        0x39, 0x45, 0xD4, 0x38, 0x84, 0xFD, 0x61, 0x25
};


//First 16 bytes of ciphertext (from bytes 16 to 32 of encrypted message - after the "Salted__" and 8 byte salt).
//More than enough to check for {"kty":"RSA"
const char ciphertexthex[] = {
        0x30, 0x69, 0xBB, 0x3E, 0xA9, 0x2A, 0x31, 0xF2, 0x4B, 0xE6, 0x98, 0xE9,
        0x72, 0xC5, 0x58, 0x01
};



///////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////
