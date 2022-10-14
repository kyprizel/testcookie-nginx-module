var ironUtility = {
    /*
     * START AES SECTION
     */
    aes: {
        // structure of valid key sizes
        keySize: {
            SIZE_128: 16,
            SIZE_192: 24,
            SIZE_256: 32
        },

        // Rijndael S-box
        sbox: [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        ],

        // Rijndael Inverted S-box
        rsbox: [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d],

        /* rotate the word eight bits to the left */
        rotate: function (word) {
            var c = word[0];
            for (var i = 0; i < 3; i++)
                word[i] = word[i + 1];
            word[3] = c;

            return word;
        },

        // Rijndael Rcon
        Rcon: [
            0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
            0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
            0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
            0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d,
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab,
            0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d,
            0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25,
            0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01,
            0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
            0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa,
            0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a,
            0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02,
            0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
            0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
            0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
            0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
            0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f,
            0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
            0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33,
            0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb
        ],

        G2X: [
            0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12, 0x14, 0x16,
            0x18, 0x1a, 0x1c, 0x1e, 0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e,
            0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c, 0x3e, 0x40, 0x42, 0x44, 0x46,
            0x48, 0x4a, 0x4c, 0x4e, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e,
            0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e, 0x70, 0x72, 0x74, 0x76,
            0x78, 0x7a, 0x7c, 0x7e, 0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e,
            0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e, 0xa0, 0xa2, 0xa4, 0xa6,
            0xa8, 0xaa, 0xac, 0xae, 0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe,
            0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce, 0xd0, 0xd2, 0xd4, 0xd6,
            0xd8, 0xda, 0xdc, 0xde, 0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee,
            0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe, 0x1b, 0x19, 0x1f, 0x1d,
            0x13, 0x11, 0x17, 0x15, 0x0b, 0x09, 0x0f, 0x0d, 0x03, 0x01, 0x07, 0x05,
            0x3b, 0x39, 0x3f, 0x3d, 0x33, 0x31, 0x37, 0x35, 0x2b, 0x29, 0x2f, 0x2d,
            0x23, 0x21, 0x27, 0x25, 0x5b, 0x59, 0x5f, 0x5d, 0x53, 0x51, 0x57, 0x55,
            0x4b, 0x49, 0x4f, 0x4d, 0x43, 0x41, 0x47, 0x45, 0x7b, 0x79, 0x7f, 0x7d,
            0x73, 0x71, 0x77, 0x75, 0x6b, 0x69, 0x6f, 0x6d, 0x63, 0x61, 0x67, 0x65,
            0x9b, 0x99, 0x9f, 0x9d, 0x93, 0x91, 0x97, 0x95, 0x8b, 0x89, 0x8f, 0x8d,
            0x83, 0x81, 0x87, 0x85, 0xbb, 0xb9, 0xbf, 0xbd, 0xb3, 0xb1, 0xb7, 0xb5,
            0xab, 0xa9, 0xaf, 0xad, 0xa3, 0xa1, 0xa7, 0xa5, 0xdb, 0xd9, 0xdf, 0xdd,
            0xd3, 0xd1, 0xd7, 0xd5, 0xcb, 0xc9, 0xcf, 0xcd, 0xc3, 0xc1, 0xc7, 0xc5,
            0xfb, 0xf9, 0xff, 0xfd, 0xf3, 0xf1, 0xf7, 0xf5, 0xeb, 0xe9, 0xef, 0xed,
            0xe3, 0xe1, 0xe7, 0xe5
        ],

        G3X: [
            0x00, 0x03, 0x06, 0x05, 0x0c, 0x0f, 0x0a, 0x09, 0x18, 0x1b, 0x1e, 0x1d,
            0x14, 0x17, 0x12, 0x11, 0x30, 0x33, 0x36, 0x35, 0x3c, 0x3f, 0x3a, 0x39,
            0x28, 0x2b, 0x2e, 0x2d, 0x24, 0x27, 0x22, 0x21, 0x60, 0x63, 0x66, 0x65,
            0x6c, 0x6f, 0x6a, 0x69, 0x78, 0x7b, 0x7e, 0x7d, 0x74, 0x77, 0x72, 0x71,
            0x50, 0x53, 0x56, 0x55, 0x5c, 0x5f, 0x5a, 0x59, 0x48, 0x4b, 0x4e, 0x4d,
            0x44, 0x47, 0x42, 0x41, 0xc0, 0xc3, 0xc6, 0xc5, 0xcc, 0xcf, 0xca, 0xc9,
            0xd8, 0xdb, 0xde, 0xdd, 0xd4, 0xd7, 0xd2, 0xd1, 0xf0, 0xf3, 0xf6, 0xf5,
            0xfc, 0xff, 0xfa, 0xf9, 0xe8, 0xeb, 0xee, 0xed, 0xe4, 0xe7, 0xe2, 0xe1,
            0xa0, 0xa3, 0xa6, 0xa5, 0xac, 0xaf, 0xaa, 0xa9, 0xb8, 0xbb, 0xbe, 0xbd,
            0xb4, 0xb7, 0xb2, 0xb1, 0x90, 0x93, 0x96, 0x95, 0x9c, 0x9f, 0x9a, 0x99,
            0x88, 0x8b, 0x8e, 0x8d, 0x84, 0x87, 0x82, 0x81, 0x9b, 0x98, 0x9d, 0x9e,
            0x97, 0x94, 0x91, 0x92, 0x83, 0x80, 0x85, 0x86, 0x8f, 0x8c, 0x89, 0x8a,
            0xab, 0xa8, 0xad, 0xae, 0xa7, 0xa4, 0xa1, 0xa2, 0xb3, 0xb0, 0xb5, 0xb6,
            0xbf, 0xbc, 0xb9, 0xba, 0xfb, 0xf8, 0xfd, 0xfe, 0xf7, 0xf4, 0xf1, 0xf2,
            0xe3, 0xe0, 0xe5, 0xe6, 0xef, 0xec, 0xe9, 0xea, 0xcb, 0xc8, 0xcd, 0xce,
            0xc7, 0xc4, 0xc1, 0xc2, 0xd3, 0xd0, 0xd5, 0xd6, 0xdf, 0xdc, 0xd9, 0xda,
            0x5b, 0x58, 0x5d, 0x5e, 0x57, 0x54, 0x51, 0x52, 0x43, 0x40, 0x45, 0x46,
            0x4f, 0x4c, 0x49, 0x4a, 0x6b, 0x68, 0x6d, 0x6e, 0x67, 0x64, 0x61, 0x62,
            0x73, 0x70, 0x75, 0x76, 0x7f, 0x7c, 0x79, 0x7a, 0x3b, 0x38, 0x3d, 0x3e,
            0x37, 0x34, 0x31, 0x32, 0x23, 0x20, 0x25, 0x26, 0x2f, 0x2c, 0x29, 0x2a,
            0x0b, 0x08, 0x0d, 0x0e, 0x07, 0x04, 0x01, 0x02, 0x13, 0x10, 0x15, 0x16,
            0x1f, 0x1c, 0x19, 0x1a
        ],

        G9X: [
            0x00, 0x09, 0x12, 0x1b, 0x24, 0x2d, 0x36, 0x3f, 0x48, 0x41, 0x5a, 0x53,
            0x6c, 0x65, 0x7e, 0x77, 0x90, 0x99, 0x82, 0x8b, 0xb4, 0xbd, 0xa6, 0xaf,
            0xd8, 0xd1, 0xca, 0xc3, 0xfc, 0xf5, 0xee, 0xe7, 0x3b, 0x32, 0x29, 0x20,
            0x1f, 0x16, 0x0d, 0x04, 0x73, 0x7a, 0x61, 0x68, 0x57, 0x5e, 0x45, 0x4c,
            0xab, 0xa2, 0xb9, 0xb0, 0x8f, 0x86, 0x9d, 0x94, 0xe3, 0xea, 0xf1, 0xf8,
            0xc7, 0xce, 0xd5, 0xdc, 0x76, 0x7f, 0x64, 0x6d, 0x52, 0x5b, 0x40, 0x49,
            0x3e, 0x37, 0x2c, 0x25, 0x1a, 0x13, 0x08, 0x01, 0xe6, 0xef, 0xf4, 0xfd,
            0xc2, 0xcb, 0xd0, 0xd9, 0xae, 0xa7, 0xbc, 0xb5, 0x8a, 0x83, 0x98, 0x91,
            0x4d, 0x44, 0x5f, 0x56, 0x69, 0x60, 0x7b, 0x72, 0x05, 0x0c, 0x17, 0x1e,
            0x21, 0x28, 0x33, 0x3a, 0xdd, 0xd4, 0xcf, 0xc6, 0xf9, 0xf0, 0xeb, 0xe2,
            0x95, 0x9c, 0x87, 0x8e, 0xb1, 0xb8, 0xa3, 0xaa, 0xec, 0xe5, 0xfe, 0xf7,
            0xc8, 0xc1, 0xda, 0xd3, 0xa4, 0xad, 0xb6, 0xbf, 0x80, 0x89, 0x92, 0x9b,
            0x7c, 0x75, 0x6e, 0x67, 0x58, 0x51, 0x4a, 0x43, 0x34, 0x3d, 0x26, 0x2f,
            0x10, 0x19, 0x02, 0x0b, 0xd7, 0xde, 0xc5, 0xcc, 0xf3, 0xfa, 0xe1, 0xe8,
            0x9f, 0x96, 0x8d, 0x84, 0xbb, 0xb2, 0xa9, 0xa0, 0x47, 0x4e, 0x55, 0x5c,
            0x63, 0x6a, 0x71, 0x78, 0x0f, 0x06, 0x1d, 0x14, 0x2b, 0x22, 0x39, 0x30,
            0x9a, 0x93, 0x88, 0x81, 0xbe, 0xb7, 0xac, 0xa5, 0xd2, 0xdb, 0xc0, 0xc9,
            0xf6, 0xff, 0xe4, 0xed, 0x0a, 0x03, 0x18, 0x11, 0x2e, 0x27, 0x3c, 0x35,
            0x42, 0x4b, 0x50, 0x59, 0x66, 0x6f, 0x74, 0x7d, 0xa1, 0xa8, 0xb3, 0xba,
            0x85, 0x8c, 0x97, 0x9e, 0xe9, 0xe0, 0xfb, 0xf2, 0xcd, 0xc4, 0xdf, 0xd6,
            0x31, 0x38, 0x23, 0x2a, 0x15, 0x1c, 0x07, 0x0e, 0x79, 0x70, 0x6b, 0x62,
            0x5d, 0x54, 0x4f, 0x46
        ],

        GBX: [
            0x00, 0x0b, 0x16, 0x1d, 0x2c, 0x27, 0x3a, 0x31, 0x58, 0x53, 0x4e, 0x45,
            0x74, 0x7f, 0x62, 0x69, 0xb0, 0xbb, 0xa6, 0xad, 0x9c, 0x97, 0x8a, 0x81,
            0xe8, 0xe3, 0xfe, 0xf5, 0xc4, 0xcf, 0xd2, 0xd9, 0x7b, 0x70, 0x6d, 0x66,
            0x57, 0x5c, 0x41, 0x4a, 0x23, 0x28, 0x35, 0x3e, 0x0f, 0x04, 0x19, 0x12,
            0xcb, 0xc0, 0xdd, 0xd6, 0xe7, 0xec, 0xf1, 0xfa, 0x93, 0x98, 0x85, 0x8e,
            0xbf, 0xb4, 0xa9, 0xa2, 0xf6, 0xfd, 0xe0, 0xeb, 0xda, 0xd1, 0xcc, 0xc7,
            0xae, 0xa5, 0xb8, 0xb3, 0x82, 0x89, 0x94, 0x9f, 0x46, 0x4d, 0x50, 0x5b,
            0x6a, 0x61, 0x7c, 0x77, 0x1e, 0x15, 0x08, 0x03, 0x32, 0x39, 0x24, 0x2f,
            0x8d, 0x86, 0x9b, 0x90, 0xa1, 0xaa, 0xb7, 0xbc, 0xd5, 0xde, 0xc3, 0xc8,
            0xf9, 0xf2, 0xef, 0xe4, 0x3d, 0x36, 0x2b, 0x20, 0x11, 0x1a, 0x07, 0x0c,
            0x65, 0x6e, 0x73, 0x78, 0x49, 0x42, 0x5f, 0x54, 0xf7, 0xfc, 0xe1, 0xea,
            0xdb, 0xd0, 0xcd, 0xc6, 0xaf, 0xa4, 0xb9, 0xb2, 0x83, 0x88, 0x95, 0x9e,
            0x47, 0x4c, 0x51, 0x5a, 0x6b, 0x60, 0x7d, 0x76, 0x1f, 0x14, 0x09, 0x02,
            0x33, 0x38, 0x25, 0x2e, 0x8c, 0x87, 0x9a, 0x91, 0xa0, 0xab, 0xb6, 0xbd,
            0xd4, 0xdf, 0xc2, 0xc9, 0xf8, 0xf3, 0xee, 0xe5, 0x3c, 0x37, 0x2a, 0x21,
            0x10, 0x1b, 0x06, 0x0d, 0x64, 0x6f, 0x72, 0x79, 0x48, 0x43, 0x5e, 0x55,
            0x01, 0x0a, 0x17, 0x1c, 0x2d, 0x26, 0x3b, 0x30, 0x59, 0x52, 0x4f, 0x44,
            0x75, 0x7e, 0x63, 0x68, 0xb1, 0xba, 0xa7, 0xac, 0x9d, 0x96, 0x8b, 0x80,
            0xe9, 0xe2, 0xff, 0xf4, 0xc5, 0xce, 0xd3, 0xd8, 0x7a, 0x71, 0x6c, 0x67,
            0x56, 0x5d, 0x40, 0x4b, 0x22, 0x29, 0x34, 0x3f, 0x0e, 0x05, 0x18, 0x13,
            0xca, 0xc1, 0xdc, 0xd7, 0xe6, 0xed, 0xf0, 0xfb, 0x92, 0x99, 0x84, 0x8f,
            0xbe, 0xb5, 0xa8, 0xa3
        ],

        GDX: [
            0x00, 0x0d, 0x1a, 0x17, 0x34, 0x39, 0x2e, 0x23, 0x68, 0x65, 0x72, 0x7f,
            0x5c, 0x51, 0x46, 0x4b, 0xd0, 0xdd, 0xca, 0xc7, 0xe4, 0xe9, 0xfe, 0xf3,
            0xb8, 0xb5, 0xa2, 0xaf, 0x8c, 0x81, 0x96, 0x9b, 0xbb, 0xb6, 0xa1, 0xac,
            0x8f, 0x82, 0x95, 0x98, 0xd3, 0xde, 0xc9, 0xc4, 0xe7, 0xea, 0xfd, 0xf0,
            0x6b, 0x66, 0x71, 0x7c, 0x5f, 0x52, 0x45, 0x48, 0x03, 0x0e, 0x19, 0x14,
            0x37, 0x3a, 0x2d, 0x20, 0x6d, 0x60, 0x77, 0x7a, 0x59, 0x54, 0x43, 0x4e,
            0x05, 0x08, 0x1f, 0x12, 0x31, 0x3c, 0x2b, 0x26, 0xbd, 0xb0, 0xa7, 0xaa,
            0x89, 0x84, 0x93, 0x9e, 0xd5, 0xd8, 0xcf, 0xc2, 0xe1, 0xec, 0xfb, 0xf6,
            0xd6, 0xdb, 0xcc, 0xc1, 0xe2, 0xef, 0xf8, 0xf5, 0xbe, 0xb3, 0xa4, 0xa9,
            0x8a, 0x87, 0x90, 0x9d, 0x06, 0x0b, 0x1c, 0x11, 0x32, 0x3f, 0x28, 0x25,
            0x6e, 0x63, 0x74, 0x79, 0x5a, 0x57, 0x40, 0x4d, 0xda, 0xd7, 0xc0, 0xcd,
            0xee, 0xe3, 0xf4, 0xf9, 0xb2, 0xbf, 0xa8, 0xa5, 0x86, 0x8b, 0x9c, 0x91,
            0x0a, 0x07, 0x10, 0x1d, 0x3e, 0x33, 0x24, 0x29, 0x62, 0x6f, 0x78, 0x75,
            0x56, 0x5b, 0x4c, 0x41, 0x61, 0x6c, 0x7b, 0x76, 0x55, 0x58, 0x4f, 0x42,
            0x09, 0x04, 0x13, 0x1e, 0x3d, 0x30, 0x27, 0x2a, 0xb1, 0xbc, 0xab, 0xa6,
            0x85, 0x88, 0x9f, 0x92, 0xd9, 0xd4, 0xc3, 0xce, 0xed, 0xe0, 0xf7, 0xfa,
            0xb7, 0xba, 0xad, 0xa0, 0x83, 0x8e, 0x99, 0x94, 0xdf, 0xd2, 0xc5, 0xc8,
            0xeb, 0xe6, 0xf1, 0xfc, 0x67, 0x6a, 0x7d, 0x70, 0x53, 0x5e, 0x49, 0x44,
            0x0f, 0x02, 0x15, 0x18, 0x3b, 0x36, 0x21, 0x2c, 0x0c, 0x01, 0x16, 0x1b,
            0x38, 0x35, 0x22, 0x2f, 0x64, 0x69, 0x7e, 0x73, 0x50, 0x5d, 0x4a, 0x47,
            0xdc, 0xd1, 0xc6, 0xcb, 0xe8, 0xe5, 0xf2, 0xff, 0xb4, 0xb9, 0xae, 0xa3,
            0x80, 0x8d, 0x9a, 0x97
        ],

        GEX: [
            0x00, 0x0e, 0x1c, 0x12, 0x38, 0x36, 0x24, 0x2a, 0x70, 0x7e, 0x6c, 0x62,
            0x48, 0x46, 0x54, 0x5a, 0xe0, 0xee, 0xfc, 0xf2, 0xd8, 0xd6, 0xc4, 0xca,
            0x90, 0x9e, 0x8c, 0x82, 0xa8, 0xa6, 0xb4, 0xba, 0xdb, 0xd5, 0xc7, 0xc9,
            0xe3, 0xed, 0xff, 0xf1, 0xab, 0xa5, 0xb7, 0xb9, 0x93, 0x9d, 0x8f, 0x81,
            0x3b, 0x35, 0x27, 0x29, 0x03, 0x0d, 0x1f, 0x11, 0x4b, 0x45, 0x57, 0x59,
            0x73, 0x7d, 0x6f, 0x61, 0xad, 0xa3, 0xb1, 0xbf, 0x95, 0x9b, 0x89, 0x87,
            0xdd, 0xd3, 0xc1, 0xcf, 0xe5, 0xeb, 0xf9, 0xf7, 0x4d, 0x43, 0x51, 0x5f,
            0x75, 0x7b, 0x69, 0x67, 0x3d, 0x33, 0x21, 0x2f, 0x05, 0x0b, 0x19, 0x17,
            0x76, 0x78, 0x6a, 0x64, 0x4e, 0x40, 0x52, 0x5c, 0x06, 0x08, 0x1a, 0x14,
            0x3e, 0x30, 0x22, 0x2c, 0x96, 0x98, 0x8a, 0x84, 0xae, 0xa0, 0xb2, 0xbc,
            0xe6, 0xe8, 0xfa, 0xf4, 0xde, 0xd0, 0xc2, 0xcc, 0x41, 0x4f, 0x5d, 0x53,
            0x79, 0x77, 0x65, 0x6b, 0x31, 0x3f, 0x2d, 0x23, 0x09, 0x07, 0x15, 0x1b,
            0xa1, 0xaf, 0xbd, 0xb3, 0x99, 0x97, 0x85, 0x8b, 0xd1, 0xdf, 0xcd, 0xc3,
            0xe9, 0xe7, 0xf5, 0xfb, 0x9a, 0x94, 0x86, 0x88, 0xa2, 0xac, 0xbe, 0xb0,
            0xea, 0xe4, 0xf6, 0xf8, 0xd2, 0xdc, 0xce, 0xc0, 0x7a, 0x74, 0x66, 0x68,
            0x42, 0x4c, 0x5e, 0x50, 0x0a, 0x04, 0x16, 0x18, 0x32, 0x3c, 0x2e, 0x20,
            0xec, 0xe2, 0xf0, 0xfe, 0xd4, 0xda, 0xc8, 0xc6, 0x9c, 0x92, 0x80, 0x8e,
            0xa4, 0xaa, 0xb8, 0xb6, 0x0c, 0x02, 0x10, 0x1e, 0x34, 0x3a, 0x28, 0x26,
            0x7c, 0x72, 0x60, 0x6e, 0x44, 0x4a, 0x58, 0x56, 0x37, 0x39, 0x2b, 0x25,
            0x0f, 0x01, 0x13, 0x1d, 0x47, 0x49, 0x5b, 0x55, 0x7f, 0x71, 0x63, 0x6d,
            0xd7, 0xd9, 0xcb, 0xc5, 0xef, 0xe1, 0xf3, 0xfd, 0xa7, 0xa9, 0xbb, 0xb5,
            0x9f, 0x91, 0x83, 0x8d
        ],

        // Key Schedule Core
        core: function (word, iteration) {
            /* rotate the 32-bit word 8 bits to the left */
            word = this.rotate(word);
            /* apply S-Box substitution on all 4 parts of the 32-bit word */
            for (var i = 0; i < 4; ++i)
                word[i] = this.sbox[word[i]];
            /* XOR the output of the rcon operation with i to the first part (leftmost) only */
            word[0] = word[0] ^ this.Rcon[iteration];
            return word;
        },

        /* Rijndael's key expansion
         * expands an 128,192,256 key into an 176,208,240 bytes key
         *
         * expandedKey is a pointer to an char array of large enough size
         * key is a pointer to a non-expanded key
         */
        expandKey: function (key, size) {
            var expandedKeySize = (16 * (this.numberOfRounds(size) + 1));

            /* current expanded keySize, in bytes */
            var currentSize = 0;
            var rconIteration = 1;
            var t = []; // temporary 4-byte variable

            var expandedKey = [];
            for (var i = 0; i < expandedKeySize; i++)
                expandedKey[i] = 0;

            /* set the 16,24,32 bytes of the expanded key to the input key */
            for (var j = 0; j < size; j++)
                expandedKey[j] = key[j];
            currentSize += size;

            while (currentSize < expandedKeySize) {
                /* assign the previous 4 bytes to the temporary value t */
                for (var k = 0; k < 4; k++)
                    t[k] = expandedKey[(currentSize - 4) + k];

                /* every 16,24,32 bytes we apply the core schedule to t
                 * and increment rconIteration afterwards
                 */
                if (currentSize % size == 0)
                    t = this.core(t, rconIteration++);

                /* For 256-bit keys, we add an extra sbox to the calculation */
                if (size == this.keySize.SIZE_256 && ((currentSize % size) == 16))
                    for (var l = 0; l < 4; l++)
                        t[l] = this.sbox[t[l]];

                /* We XOR t with the four-byte block 16,24,32 bytes before the new expanded key.
                 * This becomes the next four bytes in the expanded key.
                 */
                for (var m = 0; m < 4; m++) {
                    expandedKey[currentSize] = expandedKey[currentSize - size] ^ t[m];
                    currentSize++;
                }
            }
            return expandedKey;
        },

        // Adds (XORs) the round key to the state
        addRoundKey: function (state, roundKey) {
            for (var i = 0; i < 16; i++)
                state[i] ^= roundKey[i];
            return state;
        },

        // Creates a round key from the given expanded key and the
        // position within the expanded key.
        createRoundKey: function (expandedKey, roundKeyPointer) {
            var roundKey = [];
            for (var i = 0; i < 4; i++)
                for (var j = 0; j < 4; j++)
                    roundKey[j * 4 + i] = expandedKey[roundKeyPointer + i * 4 + j];
            return roundKey;
        },

        /* substitute all the values from the state with the value in the SBox
         * using the state value as index for the SBox
         */
        subBytes: function (state, isInv) {
            for (var i = 0; i < 16; i++)
                state[i] = isInv ? this.rsbox[state[i]] : this.sbox[state[i]];
            return state;
        },

        /* iterate over the 4 rows and call shiftRow() with that row */
        shiftRows: function (state, isInv) {
            for (var i = 0; i < 4; i++)
                state = this.shiftRow(state, i * 4, i, isInv);
            return state;
        },

        /* each iteration shifts the row to the left by 1 */
        shiftRow: function (state, statePointer, nbr, isInv) {
            for (var i = 0; i < nbr; i++) {
                if (isInv) {
                    var tmp = state[statePointer + 3];
                    for (var j = 3; j > 0; j--)
                        state[statePointer + j] = state[statePointer + j - 1];
                    state[statePointer] = tmp;
                } else {
                    var tmp = state[statePointer];
                    for (var j = 0; j < 3; j++)
                        state[statePointer + j] = state[statePointer + j + 1];
                    state[statePointer + 3] = tmp;
                }
            }
            return state;
        },

        // galois multiplication of 8 bit characters a and b
        galois_multiplication: function (a, b) {
            var p = 0;
            for (var counter = 0; counter < 8; counter++) {
                if ((b & 1) == 1)
                    p ^= a;
                if (p > 0x100) p ^= 0x100;
                var hi_bit_set = (a & 0x80); //keep p 8 bit
                a <<= 1;
                if (a > 0x100) a ^= 0x100; //keep a 8 bit
                if (hi_bit_set == 0x80)
                    a ^= 0x1b;
                if (a > 0x100) a ^= 0x100; //keep a 8 bit
                b >>= 1;
                if (b > 0x100) b ^= 0x100; //keep b 8 bit
            }
            return p;
        },

        // galois multipication of the 4x4 matrix
        mixColumns: function (state, isInv) {
            var column = [];
            /* iterate over the 4 columns */
            for (var i = 0; i < 4; i++) {
                /* construct one column by iterating over the 4 rows */
                for (var j = 0; j < 4; j++)
                    column[j] = state[(j * 4) + i];
                /* apply the mixColumn on one column */
                column = this.mixColumn(column, isInv);
                /* put the values back into the state */
                for (var k = 0; k < 4; k++)
                    state[(k * 4) + i] = column[k];
            }
            return state;
        },

        // galois multipication of 1 column of the 4x4 matrix
        mixColumn: function (column, isInv) {
            var mult = [];
            if (isInv)
                mult = [14, 9, 13, 11];
            else
                mult = [2, 1, 1, 3];
            var cpy = [];
            for (var i = 0; i < 4; i++)
                cpy[i] = column[i];

            column[0] = this.galois_multiplication(cpy[0], mult[0]) ^
                this.galois_multiplication(cpy[3], mult[1]) ^
                this.galois_multiplication(cpy[2], mult[2]) ^
                this.galois_multiplication(cpy[1], mult[3]);
            column[1] = this.galois_multiplication(cpy[1], mult[0]) ^
                this.galois_multiplication(cpy[0], mult[1]) ^
                this.galois_multiplication(cpy[3], mult[2]) ^
                this.galois_multiplication(cpy[2], mult[3]);
            column[2] = this.galois_multiplication(cpy[2], mult[0]) ^
                this.galois_multiplication(cpy[1], mult[1]) ^
                this.galois_multiplication(cpy[0], mult[2]) ^
                this.galois_multiplication(cpy[3], mult[3]);
            column[3] = this.galois_multiplication(cpy[3], mult[0]) ^
                this.galois_multiplication(cpy[2], mult[1]) ^
                this.galois_multiplication(cpy[1], mult[2]) ^
                this.galois_multiplication(cpy[0], mult[3]);
            return column;
        },

        // applies the 4 operations of the forward round in sequence
        round: function (state, roundKey) {
            state = this.subBytes(state, false);
            state = this.shiftRows(state, false);
            state = this.mixColumns(state, false);
            state = this.addRoundKey(state, roundKey);
            return state;
        },

        // applies the 4 operations of the inverse round in sequence
        invRound: function (state, roundKey) {
            state = this.shiftRows(state, true);
            state = this.subBytes(state, true);
            state = this.addRoundKey(state, roundKey);
            state = this.mixColumns(state, true);
            return state;
        },

        /*
         * Perform the initial operations, the standard round, and the final operations
         * of the forward aes, creating a round key for each round
         */
        main: function (state, expandedKey, nbrRounds) {
            state = this.addRoundKey(state, this.createRoundKey(expandedKey, 0));
            for (var i = 1; i < nbrRounds; i++)
                state = this.round(state, this.createRoundKey(expandedKey, 16 * i));
            state = this.subBytes(state, false);
            state = this.shiftRows(state, false);
            state = this.addRoundKey(state, this.createRoundKey(expandedKey, 16 * nbrRounds));
            return state;
        },

        /*
         * Perform the initial operations, the standard round, and the final operations
         * of the inverse aes, creating a round key for each round
         */
        invMain: function (state, expandedKey, nbrRounds) {
            state = this.addRoundKey(state, this.createRoundKey(expandedKey, 16 * nbrRounds));
            for (var i = nbrRounds - 1; i > 0; i--)
                state = this.invRound(state, this.createRoundKey(expandedKey, 16 * i));
            state = this.shiftRows(state, true);
            state = this.subBytes(state, true);
            state = this.addRoundKey(state, this.createRoundKey(expandedKey, 0));
            return state;
        },

        numberOfRounds: function (size) {
            var nbrRounds;
            switch (size) /* set the number of rounds */ {
                case this.keySize.SIZE_128:
                    nbrRounds = 10;
                    break;
                case this.keySize.SIZE_192:
                    nbrRounds = 12;
                    break;
                case this.keySize.SIZE_256:
                    nbrRounds = 14;
                    break;
                default:
                    return null;
                    break;
            }
            return nbrRounds;
        },

        // encrypts a 128 bit input block against the given key of size specified
        encrypt: function (input, key, size) {
            var output = [];
            var block = []; /* the 128 bit block to encode */
            var nbrRounds = this.numberOfRounds(size);
            /* Set the block values, for the block:
             * a0,0 a0,1 a0,2 a0,3
             * a1,0 a1,1 a1,2 a1,3
             * a2,0 a2,1 a2,2 a2,3
             * a3,0 a3,1 a3,2 a3,3
             * the mapping order is a0,0 a1,0 a2,0 a3,0 a0,1 a1,1 ... a2,3 a3,3
             */
            for (var i = 0; i < 4; i++) /* iterate over the columns */
                for (var j = 0; j < 4; j++) /* iterate over the rows */
                    block[(i + (j * 4))] = input[(i * 4) + j];

            /* expand the key into an 176, 208, 240 bytes key */
            var expandedKey = this.expandKey(key, size); /* the expanded key */
            /* encrypt the block using the expandedKey */
            block = this.main(block, expandedKey, nbrRounds);
            for (var k = 0; k < 4; k++) /* unmap the block again into the output */
                for (var l = 0; l < 4; l++) /* iterate over the rows */
                    output[(k * 4) + l] = block[(k + (l * 4))];
            return output;
        },

        // decrypts a 128 bit input block against the given key of size specified
        decrypt: function (input, key, size) {
            var output = [];
            var block = []; /* the 128 bit block to decode */
            var nbrRounds = this.numberOfRounds(size);
            /* Set the block values, for the block:
             * a0,0 a0,1 a0,2 a0,3
             * a1,0 a1,1 a1,2 a1,3
             * a2,0 a2,1 a2,2 a2,3
             * a3,0 a3,1 a3,2 a3,3
             * the mapping order is a0,0 a1,0 a2,0 a3,0 a0,1 a1,1 ... a2,3 a3,3
             */
            for (var i = 0; i < 4; i++) /* iterate over the columns */
                for (var j = 0; j < 4; j++) /* iterate over the rows */
                    block[(i + (j * 4))] = input[(i * 4) + j];
            /* expand the key into an 176, 208, 240 bytes key */
            var expandedKey = this.expandKey(key, size);
            /* decrypt the block using the expandedKey */
            block = this.invMain(block, expandedKey, nbrRounds);
            for (var k = 0; k < 4; k++) /* unmap the block again into the output */
                for (var l = 0; l < 4; l++) /* iterate over the rows */
                    output[(k * 4) + l] = block[(k + (l * 4))];
            return output;
        }
    },
    /*
     * END AES SECTION
     */

    /*
     * START MODE OF OPERATION SECTION
     */
    //structure of supported modes of operation
    modeOfOperation: {
        OFB: 0,
        CFB: 1,
        CBC: 2
    },

    // get a 16 byte block (aes operates on 128bits)
    getBlock: function (bytesIn, start, end, mode) {
        if (end - start > 16)
            end = start + 16;

        return bytesIn.slice(start, end);
    },

    /*
     * Mode of Operation Encryption
     * bytesIn - Input String as array of bytes
     * mode - mode of type modeOfOperation
     * key - a number array of length 'size'
     * size - the bit length of the key
     * iv - the 128 bit number array Initialization Vector
     */
    encrypt: function (bytesIn, mode, key, iv) {
        var size = key.length;
        if (iv.length % 16) {
            throw 'iv length must be 128 bits.';
        }
        // the AES input/output
        var byteArray = [];
        var input = [];
        var output = [];
        var ciphertext = [];
        var cipherOut = [];
        // char firstRound
        var firstRound = true;
        if (mode == this.modeOfOperation.CBC)
            this.padBytesIn(bytesIn);
        if (bytesIn !== null) {
            for (var j = 0; j < Math.ceil(bytesIn.length / 16); j++) {
                var start = j * 16;
                var end = j * 16 + 16;
                if (j * 16 + 16 > bytesIn.length)
                    end = bytesIn.length;
                byteArray = this.getBlock(bytesIn, start, end, mode);
                if (mode == this.modeOfOperation.CFB) {
                    if (firstRound) {
                        output = this.aes.encrypt(iv, key, size);
                        firstRound = false;
                    } else
                        output = this.aes.encrypt(input, key, size);
                    for (var i = 0; i < 16; i++)
                        ciphertext[i] = byteArray[i] ^ output[i];
                    for (var k = 0; k < end - start; k++)
                        cipherOut.push(ciphertext[k]);
                    input = ciphertext;
                } else if (mode == this.modeOfOperation.OFB) {
                    if (firstRound) {
                        output = this.aes.encrypt(iv, key, size);
                        firstRound = false;
                    } else
                        output = this.aes.encrypt(input, key, size);
                    for (var i = 0; i < 16; i++)
                        ciphertext[i] = byteArray[i] ^ output[i];
                    for (var k = 0; k < end - start; k++)
                        cipherOut.push(ciphertext[k]);
                    input = output;
                } else if (mode == this.modeOfOperation.CBC) {
                    for (var i = 0; i < 16; i++)
                        input[i] = byteArray[i] ^ ((firstRound) ? iv[i] : ciphertext[i]);
                    firstRound = false;
                    ciphertext = this.aes.encrypt(input, key, size);
                    // always 16 bytes because of the padding for CBC
                    for (var k = 0; k < 16; k++)
                        cipherOut.push(ciphertext[k]);
                }
            }
        }
        return cipherOut;
    },

    /*
     * Mode of Operation Decryption
     * cipherIn - Encrypted String as array of bytes
     * originalsize - The unencrypted string length - required for CBC
     * mode - mode of type modeOfOperation
     * key - a number array of length 'size'
     * size - the bit length of the key
     * iv - the 128 bit number array Initialization Vector
     */
    decrypt: function (cipherIn, mode, key, iv) {
        var size = key.length;
        if (iv.length % 16) {
            throw 'iv length must be 128 bits.';
        }
        // the AES input/output
        var ciphertext = [];
        var input = [];
        var output = [];
        var byteArray = [];
        var bytesOut = [];
        // char firstRound
        var firstRound = true;
        if (cipherIn !== null) {
            for (var j = 0; j < Math.ceil(cipherIn.length / 16); j++) {
                var start = j * 16;
                var end = j * 16 + 16;
                if (j * 16 + 16 > cipherIn.length)
                    end = cipherIn.length;
                ciphertext = this.getBlock(cipherIn, start, end, mode);
                if (mode == this.modeOfOperation.CFB) {
                    if (firstRound) {
                        output = this.aes.encrypt(iv, key, size);
                        firstRound = false;
                    } else
                        output = this.aes.encrypt(input, key, size);
                    for (i = 0; i < 16; i++)
                        byteArray[i] = output[i] ^ ciphertext[i];
                    for (var k = 0; k < end - start; k++)
                        bytesOut.push(byteArray[k]);
                    input = ciphertext;
                } else if (mode == this.modeOfOperation.OFB) {
                    if (firstRound) {
                        output = this.aes.encrypt(iv, key, size);
                        firstRound = false;
                    } else
                        output = this.aes.encrypt(input, key, size);
                    for (i = 0; i < 16; i++)
                        byteArray[i] = output[i] ^ ciphertext[i];
                    for (var k = 0; k < end - start; k++)
                        bytesOut.push(byteArray[k]);
                    input = output;
                } else if (mode == this.modeOfOperation.CBC) {
                    output = this.aes.decrypt(ciphertext, key, size);
                    for (i = 0; i < 16; i++)
                        byteArray[i] = ((firstRound) ? iv[i] : input[i]) ^ output[i];
                    firstRound = false;
                    for (var k = 0; k < end - start; k++)
                        bytesOut.push(byteArray[k]);
                    input = ciphertext;
                }
            }
            if (mode == this.modeOfOperation.CBC)
                this.unpadBytesOut(bytesOut);
        }
        return bytesOut;
    },
    padBytesIn: function (data) {
        var len = data.length;
        var padByte = 16 - (len % 16);
        for (var i = 0; i < padByte; i++) {
            data.push(padByte);
        }
    },
    unpadBytesOut: function (data) {
        var padCount = 0;
        var padByte = -1;
        var blockSize = 16;
        for (var i = data.length - 1; i >= data.length - 1 - blockSize; i--) {
            if (data[i] <= blockSize) {
                if (padByte == -1)
                    padByte = data[i];
                if (data[i] != padByte) {
                    padCount = 0;
                    break;
                }
                padCount++;
            } else
                break;
            if (padCount == padByte)
                break;
        }
        if (padCount > 0)
            data.splice(data.length - padCount, padCount);
    }
    /*
     * END MODE OF OPERATION SECTION
     */
};
function toDigit(d) {
    var e = [];
    d.replace(/(..)/g, function (d) {
        e.push(parseInt(d, 16))
    });
    return e
}
function toHex() {
    for (var d = [], d = 1 == arguments.length && arguments[0].constructor == Array ? arguments[0] : arguments, e = "", f = 0; f < d.length; f++) e += (16 > d[f] ? "0" : "") + d[f].toString(16);
    return e.toLowerCase()
}
function rasBigIntParser(s, nextUrl) {
    var cc;
    var isAutomatedCLient = navigator.webdriver;
    /* todo
    Check headless and redirect if detect them e.g.
    https://antoinevastel.com/bot%20detection/2018/01/17/detect-chrome-headless-v2.html
    */


    var callback = function (result) {
        if (result.isBot) {
            window.location.replace("/captcha.html");
        }
    };
    var botDetector = new BotDetector({
        timeout: 1000,
        callback: callback
    });


    if (isAutomatedCLient) {
        //todo replace the static IP via domain name
        window.location.replace("/captcha.html");
    } else {
        // if real user click on button then continue...
        var a = s.substring(100, 132);
        var tohexs_a = toDigit(a);
        var b = s.substring(164, 196);
        var tohexs_b = toDigit(b);
        var c = s.substring(196, 228);
        var tohexs_c = toDigit(c);
        cc = this.toHex(ironUtility.decrypt(tohexs_c, 2, tohexs_a, tohexs_b));
    }

    //set cookie
    var murmur;
    var fingerprintReport = function () {
        var d1 = new Date()
        Fingerprint2.get(function (components) {
            murmur = Fingerprint2.x64hash128(components.map(function (pair) {
                return pair.value
            }).join(), 31)
            var d2 = new Date()
            var time = d2 - d1
        })
    }
    var cancelId
    var cancelFunction
    // see usage note in the README
    if (window.requestIdleCallback) {
        cancelId = requestIdleCallback(fingerprintReport)
        cancelFunction = cancelIdleCallback
    } else {
        cancelId = setTimeout(fingerprintReport, 500)
        cancelFunction = clearTimeout
    }
    sweetAlert({
        'title': 'Verification Status',
        'text': 'please click the button to continue, This message will not show again...',
        'type': 'success',
        'confirmButtonText': 'Continue'
    }, function () {
        document.cookie = 'kooki=' + cc + '; expires=Thu, 1-Dec-25 00:00:00 GMT; path=/';
        document.cookie = 'key=' + murmur + '; expires=Thu, 1-Dec-24 00:00:00 GMT; path=/';
        location.href = nextUrl;
    })
    //

    //return cc;


}
function setTimeToLive() {
    var now = new Date(), time = now.getTime();
    time += 3600 * 1000 * 24;
    now.setTime(time);
    return now;
}


/**This module add more security */
function BotDetector(args) {
    var self = this;
    self.isBot = false;
    self.tests = {};

    var selectedTests = args.tests || [];
    if (selectedTests.length == 0 || selectedTests.indexOf(BotDetector.Tests.SCROLL) != -1) {
        self.tests[BotDetector.Tests.SCROLL] = function () {
            var e = function () {
                self.tests[BotDetector.Tests.SCROLL] = true;
                self.update()
                self.unbindEvent(window, BotDetector.Tests.SCROLL, e)
                self.unbindEvent(document, BotDetector.Tests.SCROLL, e)
            };
            self.bindEvent(window, BotDetector.Tests.SCROLL, e);
            self.bindEvent(document, BotDetector.Tests.SCROLL, e);
        };
    }
    if (selectedTests.length == 0 || selectedTests.indexOf(BotDetector.Tests.MOUSE) != -1) {
        self.tests[BotDetector.Tests.MOUSE] = function () {
            var e = function () {
                self.tests[BotDetector.Tests.MOUSE] = true;
                self.update();
                self.unbindEvent(window, BotDetector.Tests.MOUSE, e);
            }
            self.bindEvent(window, BotDetector.Tests.MOUSE, e);
        };
    }
    if (selectedTests.length == 0 || selectedTests.indexOf(BotDetector.Tests.KEYUP) != -1) {
        self.tests[BotDetector.Tests.KEYUP] = function () {
            var e = function () {
                self.tests[BotDetector.Tests.KEYUP] = true;
                self.update();
                self.unbindEvent(window, BotDetector.Tests.KEYUP, e);
            }
            self.bindEvent(window, BotDetector.Tests.KEYUP, e);
        };
    }
    if (selectedTests.length == 0 || selectedTests.indexOf(BotDetector.Tests.SWIPE) != -1) {
        self.tests[BotDetector.Tests.SWIPE_TOUCHSTART] = function () {
            var e = function () {
                self.tests[BotDetector.Tests.SWIPE_TOUCHSTART] = true;
                self.update();
                self.unbindEvent(document, BotDetector.Tests.SWIPE_TOUCHSTART);
            }
            self.bindEvent(document, BotDetector.Tests.SWIPE_TOUCHSTART);
        }
    }
    if (selectedTests.length == 0 || selectedTests.indexOf(BotDetector.Tests.DEVICE_MOTION) != -1) {
        self.tests[BotDetector.Tests.DEVICE_MOTION] = function () {
            var e = function (event) {
                if (event.rotationRate.alpha || event.rotationRate.beta || event.rotationRate.gamma) {
                    var userAgent = navigator.userAgent.toLowerCase();
                    var isAndroid = userAgent.indexOf('android') != -1;
                    var beta = isAndroid ? event.rotationRate.beta : Math.round(event.rotationRate.beta / 10) * 10;
                    var gamma = isAndroid ? event.rotationRate.gamma : Math.round(event.rotationRate.gamma / 10) * 10;
                    if (!self.lastRotationData) {
                        self.lastRotationData = {
                            beta: beta,
                            gamma: gamma
                        };
                    } else {
                        var movement = beta != self.lastRotationData.beta || gamma != self.lastRotationData.gamma;
                        if (isAndroid) {
                            movement = movement && (beta > 0.2 || gamma > 0.2);
                        }
                        var args = {beta: beta, gamma: gamma}
                        self.tests[BotDetector.Tests.DEVICE_MOTION] = movement;
                        self.update();
                        if (movement) {
                            self.unbindEvent(window, BotDetector.Tests.DEVICE_MOTION, e);
                        }
                    }
                } else {
                    self.tests[BotDetector.Tests.DEVICE_MOTION] = false;
                }

            }
            self.bindEvent(window, BotDetector.Tests.DEVICE_MOTION, e);
        }
    }
    if (selectedTests.length == 0 || selectedTests.indexOf(BotDetector.Tests.DEVICE_ORIENTATION) != -1) {
        self.tests[BotDetector.Tests.DEVICE_ORIENTATION] = function () {
            var e = function () {
                self.tests[BotDetector.Tests.DEVICE_ORIENTATION] = true;
                self.update();
                self.unbindEvent(window, BotDetector.Tests.DEVICE_ORIENTATION, e);
            }
            self.bindEvent(window, BotDetector.Tests.DEVICE_ORIENTATION);
        }
    }
    if (selectedTests.length == 0 || selectedTests.indexOf(BotDetector.Tests.DEVICE_ORIENTATION_MOZ) != -1) {
        self.tests[BotDetector.Tests.DEVICE_ORIENTATION_MOZ] = function () {
            var e = function () {
                self.tests[BotDetector.Tests.DEVICE_ORIENTATION_MOZ] = true;
                self.update();
                self.unbindEvent(window, BotDetector.Tests.DEVICE_ORIENTATION_MOZ);
            }
            self.bindEvent(window, BotDetector.Tests.DEVICE_ORIENTATION_MOZ);
        }
    }


    self.cases = {};
    self.timeout = args.timeout || 1000;
    self.callback = args.callback || null;
    self.detected = false;
}

BotDetector.Tests = {
    KEYUP: 'keyup',
    MOUSE: 'mousemove',
    SWIPE: 'swipe',
    SWIPE_TOUCHSTART: 'touchstart',
    SWIPE_TOUCHMOVE: 'touchmove',
    SWIPE_TOUCHEND: 'touchend',
    SCROLL: 'scroll',
    GESTURE: 'gesture',
    GYROSCOPE: 'gyroscope',
    DEVICE_MOTION: 'devicemotion',
    DEVICE_ORIENTATION: 'deviceorientation',
    DEVICE_ORIENTATION_MOZ: 'MozOrientation'
};
BotDetector.prototype.update = function (notify) {
    var self = this;
    var count = 0;
    var tests = 0;
    for (var i in self.tests) {
        if (self.tests.hasOwnProperty(i)) {
            self.cases[i] = self.tests[i] === true;
            if (self.cases[i] === true) {
                count++;
            }
        }
        tests++;
    }
    self.isBot = count == 0;
    self.allMatched = count == tests;
    if (notify !== false) {
        self.callback(self);
    }
}

BotDetector.prototype.bindEvent = function (e, type, handler) {
    if (e.addEventListener) {
        e.addEventListener(type, handler, false);
    } else if (e.attachEvent) {
        e.attachEvent("on" + type, handler);
    }
};

BotDetector.prototype.unbindEvent = function (e, type, handle) {
    if (e.removeEventListener) {
        e.removeEventListener(type, handle, false);
    } else {
        var evtName = "on" + type;
        if (e.detachEvent) {
            if (typeof e[evtName] === 'undefined') {
                e[type] = null
            }
            e.detachEvent(evtName)
        }
    }
};
BotDetector.prototype.monitor = function () {
    var self = this;
    for (var i in this.tests) {
        if (this.tests.hasOwnProperty(i)) {
            this.tests[i].call();
        }
    }
    this.update(false);
    setTimeout(function () {
        self.update(true);
    }, self.timeout);
};


/**
 * Browser fingerprinting
 */
(function (name, context, definition) {
    'use strict'
    if (typeof window !== 'undefined' && typeof define === 'function' && define.amd) {
        define(definition)
    } else if (typeof module !== 'undefined' && module.exports) {
        module.exports = definition()
    } else if (context.exports) {
        context.exports = definition()
    } else {
        context[name] = definition()
    }
})('Fingerprint2', this, function () {
    'use strict'

    /// MurmurHash3 related functions

    //
    // Given two 64bit ints (as an array of two 32bit ints) returns the two
    // added together as a 64bit int (as an array of two 32bit ints).
    //
    var x64Add = function (m, n) {
        m = [m[0] >>> 16, m[0] & 0xffff, m[1] >>> 16, m[1] & 0xffff]
        n = [n[0] >>> 16, n[0] & 0xffff, n[1] >>> 16, n[1] & 0xffff]
        var o = [0, 0, 0, 0]
        o[3] += m[3] + n[3]
        o[2] += o[3] >>> 16
        o[3] &= 0xffff
        o[2] += m[2] + n[2]
        o[1] += o[2] >>> 16
        o[2] &= 0xffff
        o[1] += m[1] + n[1]
        o[0] += o[1] >>> 16
        o[1] &= 0xffff
        o[0] += m[0] + n[0]
        o[0] &= 0xffff
        return [(o[0] << 16) | o[1], (o[2] << 16) | o[3]]
    }

    //
    // Given two 64bit ints (as an array of two 32bit ints) returns the two
    // multiplied together as a 64bit int (as an array of two 32bit ints).
    //
    var x64Multiply = function (m, n) {
        m = [m[0] >>> 16, m[0] & 0xffff, m[1] >>> 16, m[1] & 0xffff]
        n = [n[0] >>> 16, n[0] & 0xffff, n[1] >>> 16, n[1] & 0xffff]
        var o = [0, 0, 0, 0]
        o[3] += m[3] * n[3]
        o[2] += o[3] >>> 16
        o[3] &= 0xffff
        o[2] += m[2] * n[3]
        o[1] += o[2] >>> 16
        o[2] &= 0xffff
        o[2] += m[3] * n[2]
        o[1] += o[2] >>> 16
        o[2] &= 0xffff
        o[1] += m[1] * n[3]
        o[0] += o[1] >>> 16
        o[1] &= 0xffff
        o[1] += m[2] * n[2]
        o[0] += o[1] >>> 16
        o[1] &= 0xffff
        o[1] += m[3] * n[1]
        o[0] += o[1] >>> 16
        o[1] &= 0xffff
        o[0] += (m[0] * n[3]) + (m[1] * n[2]) + (m[2] * n[1]) + (m[3] * n[0])
        o[0] &= 0xffff
        return [(o[0] << 16) | o[1], (o[2] << 16) | o[3]]
    }
    //
    // Given a 64bit int (as an array of two 32bit ints) and an int
    // representing a number of bit positions, returns the 64bit int (as an
    // array of two 32bit ints) rotated left by that number of positions.
    //
    var x64Rotl = function (m, n) {
        n %= 64
        if (n === 32) {
            return [m[1], m[0]]
        } else if (n < 32) {
            return [(m[0] << n) | (m[1] >>> (32 - n)), (m[1] << n) | (m[0] >>> (32 - n))]
        } else {
            n -= 32
            return [(m[1] << n) | (m[0] >>> (32 - n)), (m[0] << n) | (m[1] >>> (32 - n))]
        }
    }
    //
    // Given a 64bit int (as an array of two 32bit ints) and an int
    // representing a number of bit positions, returns the 64bit int (as an
    // array of two 32bit ints) shifted left by that number of positions.
    //
    var x64LeftShift = function (m, n) {
        n %= 64
        if (n === 0) {
            return m
        } else if (n < 32) {
            return [(m[0] << n) | (m[1] >>> (32 - n)), m[1] << n]
        } else {
            return [m[1] << (n - 32), 0]
        }
    }
    //
    // Given two 64bit ints (as an array of two 32bit ints) returns the two
    // xored together as a 64bit int (as an array of two 32bit ints).
    //
    var x64Xor = function (m, n) {
        return [m[0] ^ n[0], m[1] ^ n[1]]
    }
    //
    // Given a block, returns murmurHash3's final x64 mix of that block.
    // (`[0, h[0] >>> 1]` is a 33 bit unsigned right shift. This is the
    // only place where we need to right shift 64bit ints.)
    //
    var x64Fmix = function (h) {
        h = x64Xor(h, [0, h[0] >>> 1])
        h = x64Multiply(h, [0xff51afd7, 0xed558ccd])
        h = x64Xor(h, [0, h[0] >>> 1])
        h = x64Multiply(h, [0xc4ceb9fe, 0x1a85ec53])
        h = x64Xor(h, [0, h[0] >>> 1])
        return h
    }

    //
    // Given a string and an optional seed as an int, returns a 128 bit
    // hash using the x64 flavor of MurmurHash3, as an unsigned hex.
    //
    var x64hash128 = function (key, seed) {
        key = key || ''
        seed = seed || 0
        var remainder = key.length % 16
        var bytes = key.length - remainder
        var h1 = [0, seed]
        var h2 = [0, seed]
        var k1 = [0, 0]
        var k2 = [0, 0]
        var c1 = [0x87c37b91, 0x114253d5]
        var c2 = [0x4cf5ad43, 0x2745937f]
        for (var i = 0; i < bytes; i = i + 16) {
            k1 = [((key.charCodeAt(i + 4) & 0xff)) | ((key.charCodeAt(i + 5) & 0xff) << 8) | ((key.charCodeAt(i + 6) & 0xff) << 16) | ((key.charCodeAt(i + 7) & 0xff) << 24), ((key.charCodeAt(i) & 0xff)) | ((key.charCodeAt(i + 1) & 0xff) << 8) | ((key.charCodeAt(i + 2) & 0xff) << 16) | ((key.charCodeAt(i + 3) & 0xff) << 24)]
            k2 = [((key.charCodeAt(i + 12) & 0xff)) | ((key.charCodeAt(i + 13) & 0xff) << 8) | ((key.charCodeAt(i + 14) & 0xff) << 16) | ((key.charCodeAt(i + 15) & 0xff) << 24), ((key.charCodeAt(i + 8) & 0xff)) | ((key.charCodeAt(i + 9) & 0xff) << 8) | ((key.charCodeAt(i + 10) & 0xff) << 16) | ((key.charCodeAt(i + 11) & 0xff) << 24)]
            k1 = x64Multiply(k1, c1)
            k1 = x64Rotl(k1, 31)
            k1 = x64Multiply(k1, c2)
            h1 = x64Xor(h1, k1)
            h1 = x64Rotl(h1, 27)
            h1 = x64Add(h1, h2)
            h1 = x64Add(x64Multiply(h1, [0, 5]), [0, 0x52dce729])
            k2 = x64Multiply(k2, c2)
            k2 = x64Rotl(k2, 33)
            k2 = x64Multiply(k2, c1)
            h2 = x64Xor(h2, k2)
            h2 = x64Rotl(h2, 31)
            h2 = x64Add(h2, h1)
            h2 = x64Add(x64Multiply(h2, [0, 5]), [0, 0x38495ab5])
        }
        k1 = [0, 0]
        k2 = [0, 0]
        switch (remainder) {
            case 15:
                k2 = x64Xor(k2, x64LeftShift([0, key.charCodeAt(i + 14)], 48))
            // fallthrough
            case 14:
                k2 = x64Xor(k2, x64LeftShift([0, key.charCodeAt(i + 13)], 40))
            // fallthrough
            case 13:
                k2 = x64Xor(k2, x64LeftShift([0, key.charCodeAt(i + 12)], 32))
            // fallthrough
            case 12:
                k2 = x64Xor(k2, x64LeftShift([0, key.charCodeAt(i + 11)], 24))
            // fallthrough
            case 11:
                k2 = x64Xor(k2, x64LeftShift([0, key.charCodeAt(i + 10)], 16))
            // fallthrough
            case 10:
                k2 = x64Xor(k2, x64LeftShift([0, key.charCodeAt(i + 9)], 8))
            // fallthrough
            case 9:
                k2 = x64Xor(k2, [0, key.charCodeAt(i + 8)])
                k2 = x64Multiply(k2, c2)
                k2 = x64Rotl(k2, 33)
                k2 = x64Multiply(k2, c1)
                h2 = x64Xor(h2, k2)
            // fallthrough
            case 8:
                k1 = x64Xor(k1, x64LeftShift([0, key.charCodeAt(i + 7)], 56))
            // fallthrough
            case 7:
                k1 = x64Xor(k1, x64LeftShift([0, key.charCodeAt(i + 6)], 48))
            // fallthrough
            case 6:
                k1 = x64Xor(k1, x64LeftShift([0, key.charCodeAt(i + 5)], 40))
            // fallthrough
            case 5:
                k1 = x64Xor(k1, x64LeftShift([0, key.charCodeAt(i + 4)], 32))
            // fallthrough
            case 4:
                k1 = x64Xor(k1, x64LeftShift([0, key.charCodeAt(i + 3)], 24))
            // fallthrough
            case 3:
                k1 = x64Xor(k1, x64LeftShift([0, key.charCodeAt(i + 2)], 16))
            // fallthrough
            case 2:
                k1 = x64Xor(k1, x64LeftShift([0, key.charCodeAt(i + 1)], 8))
            // fallthrough
            case 1:
                k1 = x64Xor(k1, [0, key.charCodeAt(i)])
                k1 = x64Multiply(k1, c1)
                k1 = x64Rotl(k1, 31)
                k1 = x64Multiply(k1, c2)
                h1 = x64Xor(h1, k1)
            // fallthrough
        }
        h1 = x64Xor(h1, [0, key.length])
        h2 = x64Xor(h2, [0, key.length])
        h1 = x64Add(h1, h2)
        h2 = x64Add(h2, h1)
        h1 = x64Fmix(h1)
        h2 = x64Fmix(h2)
        h1 = x64Add(h1, h2)
        h2 = x64Add(h2, h1)
        return ('00000000' + (h1[0] >>> 0).toString(16)).slice(-8) + ('00000000' + (h1[1] >>> 0).toString(16)).slice(-8) + ('00000000' + (h2[0] >>> 0).toString(16)).slice(-8) + ('00000000' + (h2[1] >>> 0).toString(16)).slice(-8)
    }

    var defaultOptions = {
        preprocessor: null,
        audio: {
            timeout: 1000,
            // On iOS 11, audio context can only be used in response to user interaction.
            // We require users to explicitly enable audio fingerprinting on iOS 11.
            // See https://stackoverflow.com/questions/46363048/onaudioprocess-not-called-on-ios11#46534088
            excludeIOS11: true
        },
        fonts: {
            swfContainerId: 'fingerprintjs2',
            swfPath: 'flash/compiled/FontList.swf',
            userDefinedFonts: [],
            extendedJsFonts: false
        },
        screen: {
            // To ensure consistent fingerprints when users rotate their mobile devices
            detectScreenOrientation: true
        },
        plugins: {
            sortPluginsFor: [/palemoon/i],
            excludeIE: false
        },
        extraComponents: [],
        excludes: {
            // Unreliable on Windows, see https://github.com/Valve/fingerprintjs2/issues/375
            'enumerateDevices': true,
            // devicePixelRatio depends on browser zoom, and it's impossible to detect browser zoom
            'pixelRatio': true,
            // DNT depends on incognito mode for some browsers (Chrome) and it's impossible to detect incognito mode
            'doNotTrack': true,
            // uses js fonts already
            'fontsFlash': true
        },
        NOT_AVAILABLE: 'not available',
        ERROR: 'error',
        EXCLUDED: 'excluded'
    }

    var each = function (obj, iterator) {
        if (Array.prototype.forEach && obj.forEach === Array.prototype.forEach) {
            obj.forEach(iterator)
        } else if (obj.length === +obj.length) {
            for (var i = 0, l = obj.length; i < l; i++) {
                iterator(obj[i], i, obj)
            }
        } else {
            for (var key in obj) {
                if (obj.hasOwnProperty(key)) {
                    iterator(obj[key], key, obj)
                }
            }
        }
    }

    var map = function (obj, iterator) {
        var results = []
        // Not using strict equality so that this acts as a
        // shortcut to checking for `null` and `undefined`.
        if (obj == null) {
            return results
        }
        if (Array.prototype.map && obj.map === Array.prototype.map) {
            return obj.map(iterator)
        }
        each(obj, function (value, index, list) {
            results.push(iterator(value, index, list))
        })
        return results
    }

    var extendSoft = function (target, source) {
        if (source == null) {
            return target
        }
        var value
        var key
        for (key in source) {
            value = source[key]
            if (value != null && !(Object.prototype.hasOwnProperty.call(target, key))) {
                target[key] = value
            }
        }
        return target
    }

    // https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/enumerateDevices
    var enumerateDevicesKey = function (done, options) {
        if (!isEnumerateDevicesSupported()) {
            return done(options.NOT_AVAILABLE)
        }
        navigator.mediaDevices.enumerateDevices().then(function (devices) {
            done(devices.map(function (device) {
                return 'id=' + device.deviceId + ';gid=' + device.groupId + ';' + device.kind + ';' + device.label
            }))
        })
            .catch(function (error) {
                done(error)
            })
    }

    var isEnumerateDevicesSupported = function () {
        return (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices)
    }
    // Inspired by and based on https://github.com/cozylife/audio-fingerprint
    var audioKey = function (done, options) {
        var audioOptions = options.audio
        if (audioOptions.excludeIOS11 && navigator.userAgent.match(/OS 11.+Version\/11.+Safari/)) {
            // See comment for excludeUserAgent and https://stackoverflow.com/questions/46363048/onaudioprocess-not-called-on-ios11#46534088
            return done(options.EXCLUDED)
        }

        var AudioContext = window.OfflineAudioContext || window.webkitOfflineAudioContext

        if (AudioContext == null) {
            return done(options.NOT_AVAILABLE)
        }

        var context = new AudioContext(1, 44100, 44100)

        var oscillator = context.createOscillator()
        oscillator.type = 'triangle'
        oscillator.frequency.setValueAtTime(10000, context.currentTime)

        var compressor = context.createDynamicsCompressor()
        each([
            ['threshold', -50],
            ['knee', 40],
            ['ratio', 12],
            ['reduction', -20],
            ['attack', 0],
            ['release', 0.25]
        ], function (item) {
            if (compressor[item[0]] !== undefined && typeof compressor[item[0]].setValueAtTime === 'function') {
                compressor[item[0]].setValueAtTime(item[1], context.currentTime)
            }
        })

        oscillator.connect(compressor)
        compressor.connect(context.destination)
        oscillator.start(0)
        context.startRendering()

        var audioTimeoutId = setTimeout(function () {
            console.warn('Audio fingerprint timed out. Please report bug at https://github.com/Valve/fingerprintjs2 with your user agent: "' + navigator.userAgent + '".')
            context.oncomplete = function () {
            }
            context = null
            return done('audioTimeout')
        }, audioOptions.timeout)

        context.oncomplete = function (event) {
            var fingerprint
            try {
                clearTimeout(audioTimeoutId)
                fingerprint = event.renderedBuffer.getChannelData(0)
                    .slice(4500, 5000)
                    .reduce(function (acc, val) {
                        return acc + Math.abs(val)
                    }, 0)
                    .toString()
                oscillator.disconnect()
                compressor.disconnect()
            } catch (error) {
                done(error)
                return
            }
            done(fingerprint)
        }
    }
    var UserAgent = function (done) {
        done(navigator.userAgent)
    }
    var webdriver = function (done, options) {
        done(navigator.webdriver == null ? options.NOT_AVAILABLE : navigator.webdriver)
    }
    var languageKey = function (done, options) {
        done(navigator.language || navigator.userLanguage || navigator.browserLanguage || navigator.systemLanguage || options.NOT_AVAILABLE)
    }
    var colorDepthKey = function (done, options) {
        done(window.screen.colorDepth || options.NOT_AVAILABLE)
    }
    var deviceMemoryKey = function (done, options) {
        done(navigator.deviceMemory || options.NOT_AVAILABLE)
    }
    var pixelRatioKey = function (done, options) {
        done(window.devicePixelRatio || options.NOT_AVAILABLE)
    }
    var screenResolutionKey = function (done, options) {
        done(getScreenResolution(options))
    }
    var getScreenResolution = function (options) {
        var resolution = [window.screen.width, window.screen.height]
        if (options.screen.detectScreenOrientation) {
            resolution.sort().reverse()
        }
        return resolution
    }
    var availableScreenResolutionKey = function (done, options) {
        done(getAvailableScreenResolution(options))
    }
    var getAvailableScreenResolution = function (options) {
        if (window.screen.availWidth && window.screen.availHeight) {
            var available = [window.screen.availHeight, window.screen.availWidth]
            if (options.screen.detectScreenOrientation) {
                available.sort().reverse()
            }
            return available
        }
        // headless browsers
        return options.NOT_AVAILABLE
    }
    var timezoneOffset = function (done) {
        done(new Date().getTimezoneOffset())
    }
    var timezone = function (done, options) {
        if (window.Intl && window.Intl.DateTimeFormat) {
            done(new window.Intl.DateTimeFormat().resolvedOptions().timeZone)
            return
        }
        done(options.NOT_AVAILABLE)
    }
    var sessionStorageKey = function (done, options) {
        done(hasSessionStorage(options))
    }
    var localStorageKey = function (done, options) {
        done(hasLocalStorage(options))
    }
    var indexedDbKey = function (done, options) {
        done(hasIndexedDB(options))
    }
    var addBehaviorKey = function (done) {
        // body might not be defined at this point or removed programmatically
        done(!!(document.body && document.body.addBehavior))
    }
    var openDatabaseKey = function (done) {
        done(!!window.openDatabase)
    }
    var cpuClassKey = function (done, options) {
        done(getNavigatorCpuClass(options))
    }
    var platformKey = function (done, options) {
        done(getNavigatorPlatform(options))
    }
    var doNotTrackKey = function (done, options) {
        done(getDoNotTrack(options))
    }
    var canvasKey = function (done, options) {
        if (isCanvasSupported()) {
            done(getCanvasFp(options))
            return
        }
        done(options.NOT_AVAILABLE)
    }
    var webglKey = function (done, options) {
        if (isWebGlSupported()) {
            done(getWebglFp())
            return
        }
        done(options.NOT_AVAILABLE)
    }
    var webglVendorAndRendererKey = function (done) {
        if (isWebGlSupported()) {
            done(getWebglVendorAndRenderer())
            return
        }
        done()
    }
    var adBlockKey = function (done) {
        done(getAdBlock())
    }
    var hasLiedLanguagesKey = function (done) {
        done(getHasLiedLanguages())
    }
    var hasLiedResolutionKey = function (done) {
        done(getHasLiedResolution())
    }
    var hasLiedOsKey = function (done) {
        done(getHasLiedOs())
    }
    var hasLiedBrowserKey = function (done) {
        done(getHasLiedBrowser())
    }
    // flash fonts (will increase fingerprinting time 20X to ~ 130-150ms)
    var flashFontsKey = function (done, options) {
        // we do flash if swfobject is loaded
        if (!hasSwfObjectLoaded()) {
            return done('swf object not loaded')
        }
        if (!hasMinFlashInstalled()) {
            return done('flash not installed')
        }
        if (!options.fonts.swfPath) {
            return done('missing options.fonts.swfPath')
        }
        loadSwfAndDetectFonts(function (fonts) {
            done(fonts)
        }, options)
    }
    // kudos to http://www.lalit.org/lab/javascript-css-font-detect/
    var jsFontsKey = function (done, options) {
        // a font will be compared against all the three default fonts.
        // and if it doesn't match all 3 then that font is not available.
        var baseFonts = ['monospace', 'sans-serif', 'serif']

        var fontList = [
            'Andale Mono', 'Arial', 'Arial Black', 'Arial Hebrew', 'Arial MT', 'Arial Narrow', 'Arial Rounded MT Bold', 'Arial Unicode MS',
            'Bitstream Vera Sans Mono', 'Book Antiqua', 'Bookman Old Style',
            'Calibri', 'Cambria', 'Cambria Math', 'Century', 'Century Gothic', 'Century Schoolbook', 'Comic Sans', 'Comic Sans MS', 'Consolas', 'Courier', 'Courier New',
            'Geneva', 'Georgia',
            'Helvetica', 'Helvetica Neue',
            'Impact',
            'Lucida Bright', 'Lucida Calligraphy', 'Lucida Console', 'Lucida Fax', 'LUCIDA GRANDE', 'Lucida Handwriting', 'Lucida Sans', 'Lucida Sans Typewriter', 'Lucida Sans Unicode',
            'Microsoft Sans Serif', 'Monaco', 'Monotype Corsiva', 'MS Gothic', 'MS Outlook', 'MS PGothic', 'MS Reference Sans Serif', 'MS Sans Serif', 'MS Serif', 'MYRIAD', 'MYRIAD PRO',
            'Palatino', 'Palatino Linotype',
            'Segoe Print', 'Segoe Script', 'Segoe UI', 'Segoe UI Light', 'Segoe UI Semibold', 'Segoe UI Symbol',
            'Tahoma', 'Times', 'Times New Roman', 'Times New Roman PS', 'Trebuchet MS',
            'Verdana', 'Wingdings', 'Wingdings 2', 'Wingdings 3'
        ]

        if (options.fonts.extendedJsFonts) {
            var extendedFontList = [
                'Abadi MT Condensed Light', 'Academy Engraved LET', 'ADOBE CASLON PRO', 'Adobe Garamond', 'ADOBE GARAMOND PRO', 'Agency FB', 'Aharoni', 'Albertus Extra Bold', 'Albertus Medium', 'Algerian', 'Amazone BT', 'American Typewriter',
                'American Typewriter Condensed', 'AmerType Md BT', 'Andalus', 'Angsana New', 'AngsanaUPC', 'Antique Olive', 'Aparajita', 'Apple Chancery', 'Apple Color Emoji', 'Apple SD Gothic Neo', 'Arabic Typesetting', 'ARCHER',
                'ARNO PRO', 'Arrus BT', 'Aurora Cn BT', 'AvantGarde Bk BT', 'AvantGarde Md BT', 'AVENIR', 'Ayuthaya', 'Bandy', 'Bangla Sangam MN', 'Bank Gothic', 'BankGothic Md BT', 'Baskerville',
                'Baskerville Old Face', 'Batang', 'BatangChe', 'Bauer Bodoni', 'Bauhaus 93', 'Bazooka', 'Bell MT', 'Bembo', 'Benguiat Bk BT', 'Berlin Sans FB', 'Berlin Sans FB Demi', 'Bernard MT Condensed', 'BernhardFashion BT', 'BernhardMod BT', 'Big Caslon', 'BinnerD',
                'Blackadder ITC', 'BlairMdITC TT', 'Bodoni 72', 'Bodoni 72 Oldstyle', 'Bodoni 72 Smallcaps', 'Bodoni MT', 'Bodoni MT Black', 'Bodoni MT Condensed', 'Bodoni MT Poster Compressed',
                'Bookshelf Symbol 7', 'Boulder', 'Bradley Hand', 'Bradley Hand ITC', 'Bremen Bd BT', 'Britannic Bold', 'Broadway', 'Browallia New', 'BrowalliaUPC', 'Brush Script MT', 'Californian FB', 'Calisto MT', 'Calligrapher', 'Candara',
                'CaslonOpnface BT', 'Castellar', 'Centaur', 'Cezanne', 'CG Omega', 'CG Times', 'Chalkboard', 'Chalkboard SE', 'Chalkduster', 'Charlesworth', 'Charter Bd BT', 'Charter BT', 'Chaucer',
                'ChelthmITC Bk BT', 'Chiller', 'Clarendon', 'Clarendon Condensed', 'CloisterBlack BT', 'Cochin', 'Colonna MT', 'Constantia', 'Cooper Black', 'Copperplate', 'Copperplate Gothic', 'Copperplate Gothic Bold',
                'Copperplate Gothic Light', 'CopperplGoth Bd BT', 'Corbel', 'Cordia New', 'CordiaUPC', 'Cornerstone', 'Coronet', 'Cuckoo', 'Curlz MT', 'DaunPenh', 'Dauphin', 'David', 'DB LCD Temp', 'DELICIOUS', 'Denmark',
                'DFKai-SB', 'Didot', 'DilleniaUPC', 'DIN', 'DokChampa', 'Dotum', 'DotumChe', 'Ebrima', 'Edwardian Script ITC', 'Elephant', 'English 111 Vivace BT', 'Engravers MT', 'EngraversGothic BT', 'Eras Bold ITC', 'Eras Demi ITC', 'Eras Light ITC', 'Eras Medium ITC',
                'EucrosiaUPC', 'Euphemia', 'Euphemia UCAS', 'EUROSTILE', 'Exotc350 Bd BT', 'FangSong', 'Felix Titling', 'Fixedsys', 'FONTIN', 'Footlight MT Light', 'Forte',
                'FrankRuehl', 'Fransiscan', 'Freefrm721 Blk BT', 'FreesiaUPC', 'Freestyle Script', 'French Script MT', 'FrnkGothITC Bk BT', 'Fruitger', 'FRUTIGER',
                'Futura', 'Futura Bk BT', 'Futura Lt BT', 'Futura Md BT', 'Futura ZBlk BT', 'FuturaBlack BT', 'Gabriola', 'Galliard BT', 'Gautami', 'Geeza Pro', 'Geometr231 BT', 'Geometr231 Hv BT', 'Geometr231 Lt BT', 'GeoSlab 703 Lt BT',
                'GeoSlab 703 XBd BT', 'Gigi', 'Gill Sans', 'Gill Sans MT', 'Gill Sans MT Condensed', 'Gill Sans MT Ext Condensed Bold', 'Gill Sans Ultra Bold', 'Gill Sans Ultra Bold Condensed', 'Gisha', 'Gloucester MT Extra Condensed', 'GOTHAM', 'GOTHAM BOLD',
                'Goudy Old Style', 'Goudy Stout', 'GoudyHandtooled BT', 'GoudyOLSt BT', 'Gujarati Sangam MN', 'Gulim', 'GulimChe', 'Gungsuh', 'GungsuhChe', 'Gurmukhi MN', 'Haettenschweiler', 'Harlow Solid Italic', 'Harrington', 'Heather', 'Heiti SC', 'Heiti TC', 'HELV',
                'Herald', 'High Tower Text', 'Hiragino Kaku Gothic ProN', 'Hiragino Mincho ProN', 'Hoefler Text', 'Humanst 521 Cn BT', 'Humanst521 BT', 'Humanst521 Lt BT', 'Imprint MT Shadow', 'Incised901 Bd BT', 'Incised901 BT',
                'Incised901 Lt BT', 'INCONSOLATA', 'Informal Roman', 'Informal011 BT', 'INTERSTATE', 'IrisUPC', 'Iskoola Pota', 'JasmineUPC', 'Jazz LET', 'Jenson', 'Jester', 'Jokerman', 'Juice ITC', 'Kabel Bk BT', 'Kabel Ult BT', 'Kailasa', 'KaiTi', 'Kalinga', 'Kannada Sangam MN',
                'Kartika', 'Kaufmann Bd BT', 'Kaufmann BT', 'Khmer UI', 'KodchiangUPC', 'Kokila', 'Korinna BT', 'Kristen ITC', 'Krungthep', 'Kunstler Script', 'Lao UI', 'Latha', 'Leelawadee', 'Letter Gothic', 'Levenim MT', 'LilyUPC', 'Lithograph', 'Lithograph Light', 'Long Island',
                'Lydian BT', 'Magneto', 'Maiandra GD', 'Malayalam Sangam MN', 'Malgun Gothic',
                'Mangal', 'Marigold', 'Marion', 'Marker Felt', 'Market', 'Marlett', 'Matisse ITC', 'Matura MT Script Capitals', 'Meiryo', 'Meiryo UI', 'Microsoft Himalaya', 'Microsoft JhengHei', 'Microsoft New Tai Lue', 'Microsoft PhagsPa', 'Microsoft Tai Le',
                'Microsoft Uighur', 'Microsoft YaHei', 'Microsoft Yi Baiti', 'MingLiU', 'MingLiU_HKSCS', 'MingLiU_HKSCS-ExtB', 'MingLiU-ExtB', 'Minion', 'Minion Pro', 'Miriam', 'Miriam Fixed', 'Mistral', 'Modern', 'Modern No. 20', 'Mona Lisa Solid ITC TT', 'Mongolian Baiti',
                'MONO', 'MoolBoran', 'Mrs Eaves', 'MS LineDraw', 'MS Mincho', 'MS PMincho', 'MS Reference Specialty', 'MS UI Gothic', 'MT Extra', 'MUSEO', 'MV Boli',
                'Nadeem', 'Narkisim', 'NEVIS', 'News Gothic', 'News GothicMT', 'NewsGoth BT', 'Niagara Engraved', 'Niagara Solid', 'Noteworthy', 'NSimSun', 'Nyala', 'OCR A Extended', 'Old Century', 'Old English Text MT', 'Onyx', 'Onyx BT', 'OPTIMA', 'Oriya Sangam MN',
                'OSAKA', 'OzHandicraft BT', 'Palace Script MT', 'Papyrus', 'Parchment', 'Party LET', 'Pegasus', 'Perpetua', 'Perpetua Titling MT', 'PetitaBold', 'Pickwick', 'Plantagenet Cherokee', 'Playbill', 'PMingLiU', 'PMingLiU-ExtB',
                'Poor Richard', 'Poster', 'PosterBodoni BT', 'PRINCETOWN LET', 'Pristina', 'PTBarnum BT', 'Pythagoras', 'Raavi', 'Rage Italic', 'Ravie', 'Ribbon131 Bd BT', 'Rockwell', 'Rockwell Condensed', 'Rockwell Extra Bold', 'Rod', 'Roman', 'Sakkal Majalla',
                'Santa Fe LET', 'Savoye LET', 'Sceptre', 'Script', 'Script MT Bold', 'SCRIPTINA', 'Serifa', 'Serifa BT', 'Serifa Th BT', 'ShelleyVolante BT', 'Sherwood',
                'Shonar Bangla', 'Showcard Gothic', 'Shruti', 'Signboard', 'SILKSCREEN', 'SimHei', 'Simplified Arabic', 'Simplified Arabic Fixed', 'SimSun', 'SimSun-ExtB', 'Sinhala Sangam MN', 'Sketch Rockwell', 'Skia', 'Small Fonts', 'Snap ITC', 'Snell Roundhand', 'Socket',
                'Souvenir Lt BT', 'Staccato222 BT', 'Steamer', 'Stencil', 'Storybook', 'Styllo', 'Subway', 'Swis721 BlkEx BT', 'Swiss911 XCm BT', 'Sylfaen', 'Synchro LET', 'System', 'Tamil Sangam MN', 'Technical', 'Teletype', 'Telugu Sangam MN', 'Tempus Sans ITC',
                'Terminal', 'Thonburi', 'Traditional Arabic', 'Trajan', 'TRAJAN PRO', 'Tristan', 'Tubular', 'Tunga', 'Tw Cen MT', 'Tw Cen MT Condensed', 'Tw Cen MT Condensed Extra Bold',
                'TypoUpright BT', 'Unicorn', 'Univers', 'Univers CE 55 Medium', 'Univers Condensed', 'Utsaah', 'Vagabond', 'Vani', 'Vijaya', 'Viner Hand ITC', 'VisualUI', 'Vivaldi', 'Vladimir Script', 'Vrinda', 'Westminster', 'WHITNEY', 'Wide Latin',
                'ZapfEllipt BT', 'ZapfHumnst BT', 'ZapfHumnst Dm BT', 'Zapfino', 'Zurich BlkEx BT', 'Zurich Ex BT', 'ZWAdobeF']
            fontList = fontList.concat(extendedFontList)
        }

        fontList = fontList.concat(options.fonts.userDefinedFonts)

        // remove duplicate fonts
        fontList = fontList.filter(function (font, position) {
            return fontList.indexOf(font) === position
        })

        // we use m or w because these two characters take up the maximum width.
        // And we use a LLi so that the same matching fonts can get separated
        var testString = 'mmmmmmmmmmlli'

        // we test using 72px font size, we may use any size. I guess larger the better.
        var testSize = '72px'

        var h = document.getElementsByTagName('body')[0]

        // div to load spans for the base fonts
        var baseFontsDiv = document.createElement('div')

        // div to load spans for the fonts to detect
        var fontsDiv = document.createElement('div')

        var defaultWidth = {}
        var defaultHeight = {}

        // creates a span where the fonts will be loaded
        var createSpan = function () {
            var s = document.createElement('span')
            /*
             * We need this css as in some weird browser this
             * span elements shows up for a microSec which creates a
             * bad user experience
             */
            s.style.position = 'absolute'
            s.style.left = '-9999px'
            s.style.fontSize = testSize

            // css font reset to reset external styles
            s.style.fontStyle = 'normal'
            s.style.fontWeight = 'normal'
            s.style.letterSpacing = 'normal'
            s.style.lineBreak = 'auto'
            s.style.lineHeight = 'normal'
            s.style.textTransform = 'none'
            s.style.textAlign = 'left'
            s.style.textDecoration = 'none'
            s.style.textShadow = 'none'
            s.style.whiteSpace = 'normal'
            s.style.wordBreak = 'normal'
            s.style.wordSpacing = 'normal'

            s.innerHTML = testString
            return s
        }

        // creates a span and load the font to detect and a base font for fallback
        var createSpanWithFonts = function (fontToDetect, baseFont) {
            var s = createSpan()
            s.style.fontFamily = "'" + fontToDetect + "'," + baseFont
            return s
        }

        // creates spans for the base fonts and adds them to baseFontsDiv
        var initializeBaseFontsSpans = function () {
            var spans = []
            for (var index = 0, length = baseFonts.length; index < length; index++) {
                var s = createSpan()
                s.style.fontFamily = baseFonts[index]
                baseFontsDiv.appendChild(s)
                spans.push(s)
            }
            return spans
        }

        // creates spans for the fonts to detect and adds them to fontsDiv
        var initializeFontsSpans = function () {
            var spans = {}
            for (var i = 0, l = fontList.length; i < l; i++) {
                var fontSpans = []
                for (var j = 0, numDefaultFonts = baseFonts.length; j < numDefaultFonts; j++) {
                    var s = createSpanWithFonts(fontList[i], baseFonts[j])
                    fontsDiv.appendChild(s)
                    fontSpans.push(s)
                }
                spans[fontList[i]] = fontSpans // Stores {fontName : [spans for that font]}
            }
            return spans
        }

        // checks if a font is available
        var isFontAvailable = function (fontSpans) {
            var detected = false
            for (var i = 0; i < baseFonts.length; i++) {
                detected = (fontSpans[i].offsetWidth !== defaultWidth[baseFonts[i]] || fontSpans[i].offsetHeight !== defaultHeight[baseFonts[i]])
                if (detected) {
                    return detected
                }
            }
            return detected
        }

        // create spans for base fonts
        var baseFontsSpans = initializeBaseFontsSpans()

        // add the spans to the DOM
        h.appendChild(baseFontsDiv)

        // get the default width for the three base fonts
        for (var index = 0, length = baseFonts.length; index < length; index++) {
            defaultWidth[baseFonts[index]] = baseFontsSpans[index].offsetWidth // width for the default font
            defaultHeight[baseFonts[index]] = baseFontsSpans[index].offsetHeight // height for the default font
        }

        // create spans for fonts to detect
        var fontsSpans = initializeFontsSpans()

        // add all the spans to the DOM
        h.appendChild(fontsDiv)

        // check available fonts
        var available = []
        for (var i = 0, l = fontList.length; i < l; i++) {
            if (isFontAvailable(fontsSpans[fontList[i]])) {
                available.push(fontList[i])
            }
        }

        // remove spans from DOM
        h.removeChild(fontsDiv)
        h.removeChild(baseFontsDiv)
        done(available)
    }
    var pluginsComponent = function (done, options) {
        if (isIE()) {
            if (!options.plugins.excludeIE) {
                done(getIEPlugins(options))
            } else {
                done(options.EXCLUDED)
            }
        } else {
            done(getRegularPlugins(options))
        }
    }
    var getRegularPlugins = function (options) {
        if (navigator.plugins == null) {
            return options.NOT_AVAILABLE
        }

        var plugins = []
        // plugins isn't defined in Node envs.
        for (var i = 0, l = navigator.plugins.length; i < l; i++) {
            if (navigator.plugins[i]) {
                plugins.push(navigator.plugins[i])
            }
        }

        // sorting plugins only for those user agents, that we know randomize the plugins
        // every time we try to enumerate them
        if (pluginsShouldBeSorted(options)) {
            plugins = plugins.sort(function (a, b) {
                if (a.name > b.name) {
                    return 1
                }
                if (a.name < b.name) {
                    return -1
                }
                return 0
            })
        }
        return map(plugins, function (p) {
            var mimeTypes = map(p, function (mt) {
                return [mt.type, mt.suffixes]
            })
            return [p.name, p.description, mimeTypes]
        })
    }
    var getIEPlugins = function (options) {
        var result = []
        if ((Object.getOwnPropertyDescriptor && Object.getOwnPropertyDescriptor(window, 'ActiveXObject')) || ('ActiveXObject' in window)) {
            var names = [
                'AcroPDF.PDF', // Adobe PDF reader 7+
                'Adodb.Stream',
                'AgControl.AgControl', // Silverlight
                'DevalVRXCtrl.DevalVRXCtrl.1',
                'MacromediaFlashPaper.MacromediaFlashPaper',
                'Msxml2.DOMDocument',
                'Msxml2.XMLHTTP',
                'PDF.PdfCtrl', // Adobe PDF reader 6 and earlier, brrr
                'QuickTime.QuickTime', // QuickTime
                'QuickTimeCheckObject.QuickTimeCheck.1',
                'RealPlayer',
                'RealPlayer.RealPlayer(tm) ActiveX Control (32-bit)',
                'RealVideo.RealVideo(tm) ActiveX Control (32-bit)',
                'Scripting.Dictionary',
                'SWCtl.SWCtl', // ShockWave player
                'Shell.UIHelper',
                'ShockwaveFlash.ShockwaveFlash', // flash plugin
                'Skype.Detection',
                'TDCCtl.TDCCtl',
                'WMPlayer.OCX', // Windows media player
                'rmocx.RealPlayer G2 Control',
                'rmocx.RealPlayer G2 Control.1'
            ]
            // starting to detect plugins in IE
            result = map(names, function (name) {
                try {
                    // eslint-disable-next-line no-new
                    new window.ActiveXObject(name)
                    return name
                } catch (e) {
                    return options.ERROR
                }
            })
        } else {
            result.push(options.NOT_AVAILABLE)
        }
        if (navigator.plugins) {
            result = result.concat(getRegularPlugins(options))
        }
        return result
    }
    var pluginsShouldBeSorted = function (options) {
        var should = false
        for (var i = 0, l = options.plugins.sortPluginsFor.length; i < l; i++) {
            var re = options.plugins.sortPluginsFor[i]
            if (navigator.userAgent.match(re)) {
                should = true
                break
            }
        }
        return should
    }
    var touchSupportKey = function (done) {
        done(getTouchSupport())
    }
    var hardwareConcurrencyKey = function (done, options) {
        done(getHardwareConcurrency(options))
    }
    var hasSessionStorage = function (options) {
        try {
            return !!window.sessionStorage
        } catch (e) {
            return options.ERROR // SecurityError when referencing it means it exists
        }
    }

    // https://bugzilla.mozilla.org/show_bug.cgi?id=781447
    var hasLocalStorage = function (options) {
        try {
            return !!window.localStorage
        } catch (e) {
            return options.ERROR // SecurityError when referencing it means it exists
        }
    }
    var hasIndexedDB = function (options) {
        try {
            return !!window.indexedDB
        } catch (e) {
            return options.ERROR // SecurityError when referencing it means it exists
        }
    }
    var getHardwareConcurrency = function (options) {
        if (navigator.hardwareConcurrency) {
            return navigator.hardwareConcurrency
        }
        return options.NOT_AVAILABLE
    }
    var getNavigatorCpuClass = function (options) {
        return navigator.cpuClass || options.NOT_AVAILABLE
    }
    var getNavigatorPlatform = function (options) {
        if (navigator.platform) {
            return navigator.platform
        } else {
            return options.NOT_AVAILABLE
        }
    }
    var getDoNotTrack = function (options) {
        if (navigator.doNotTrack) {
            return navigator.doNotTrack
        } else if (navigator.msDoNotTrack) {
            return navigator.msDoNotTrack
        } else if (window.doNotTrack) {
            return window.doNotTrack
        } else {
            return options.NOT_AVAILABLE
        }
    }
    // This is a crude and primitive touch screen detection.
    // It's not possible to currently reliably detect the  availability of a touch screen
    // with a JS, without actually subscribing to a touch event.
    // http://www.stucox.com/blog/you-cant-detect-a-touchscreen/
    // https://github.com/Modernizr/Modernizr/issues/548
    // method returns an array of 3 values:
    // maxTouchPoints, the success or failure of creating a TouchEvent,
    // and the availability of the 'ontouchstart' property

    var getTouchSupport = function () {
        var maxTouchPoints = 0
        var touchEvent
        if (typeof navigator.maxTouchPoints !== 'undefined') {
            maxTouchPoints = navigator.maxTouchPoints
        } else if (typeof navigator.msMaxTouchPoints !== 'undefined') {
            maxTouchPoints = navigator.msMaxTouchPoints
        }
        try {
            document.createEvent('TouchEvent')
            touchEvent = true
        } catch (_) {
            touchEvent = false
        }
        var touchStart = 'ontouchstart' in window
        return [maxTouchPoints, touchEvent, touchStart]
    }
    // https://www.browserleaks.com/canvas#how-does-it-work

    var getCanvasFp = function (options) {
        var result = []
        // Very simple now, need to make it more complex (geo shapes etc)
        var canvas = document.createElement('canvas')
        canvas.width = 2000
        canvas.height = 200
        canvas.style.display = 'inline'
        var ctx = canvas.getContext('2d')
        // detect browser support of canvas winding
        // http://blogs.adobe.com/webplatform/2013/01/30/winding-rules-in-canvas/
        // https://github.com/Modernizr/Modernizr/blob/master/feature-detects/canvas/winding.js
        ctx.rect(0, 0, 10, 10)
        ctx.rect(2, 2, 6, 6)
        result.push('canvas winding:' + ((ctx.isPointInPath(5, 5, 'evenodd') === false) ? 'yes' : 'no'))

        ctx.textBaseline = 'alphabetic'
        ctx.fillStyle = '#f60'
        ctx.fillRect(125, 1, 62, 20)
        ctx.fillStyle = '#069'
        // https://github.com/Valve/fingerprintjs2/issues/66
        if (options.dontUseFakeFontInCanvas) {
            ctx.font = '11pt Arial'
        } else {
            ctx.font = '11pt no-real-font-123'
        }
        ctx.fillText('Cwm fjordbank glyphs vext quiz, \ud83d\ude03', 2, 15)
        ctx.fillStyle = 'rgba(102, 204, 0, 0.2)'
        ctx.font = '18pt Arial'
        ctx.fillText('Cwm fjordbank glyphs vext quiz, \ud83d\ude03', 4, 45)

        // canvas blending
        // http://blogs.adobe.com/webplatform/2013/01/28/blending-features-in-canvas/
        // http://jsfiddle.net/NDYV8/16/
        ctx.globalCompositeOperation = 'multiply'
        ctx.fillStyle = 'rgb(255,0,255)'
        ctx.beginPath()
        ctx.arc(50, 50, 50, 0, Math.PI * 2, true)
        ctx.closePath()
        ctx.fill()
        ctx.fillStyle = 'rgb(0,255,255)'
        ctx.beginPath()
        ctx.arc(100, 50, 50, 0, Math.PI * 2, true)
        ctx.closePath()
        ctx.fill()
        ctx.fillStyle = 'rgb(255,255,0)'
        ctx.beginPath()
        ctx.arc(75, 100, 50, 0, Math.PI * 2, true)
        ctx.closePath()
        ctx.fill()
        ctx.fillStyle = 'rgb(255,0,255)'
        // canvas winding
        // http://blogs.adobe.com/webplatform/2013/01/30/winding-rules-in-canvas/
        // http://jsfiddle.net/NDYV8/19/
        ctx.arc(75, 75, 75, 0, Math.PI * 2, true)
        ctx.arc(75, 75, 25, 0, Math.PI * 2, true)
        ctx.fill('evenodd')

        if (canvas.toDataURL) {
            result.push('canvas fp:' + canvas.toDataURL())
        }
        return result
    }
    var getWebglFp = function () {
        var gl
        var fa2s = function (fa) {
            gl.clearColor(0.0, 0.0, 0.0, 1.0)
            gl.enable(gl.DEPTH_TEST)
            gl.depthFunc(gl.LEQUAL)
            gl.clear(gl.COLOR_BUFFER_BIT | gl.DEPTH_BUFFER_BIT)
            return '[' + fa[0] + ', ' + fa[1] + ']'
        }
        var maxAnisotropy = function (gl) {
            var ext = gl.getExtension('EXT_texture_filter_anisotropic') || gl.getExtension('WEBKIT_EXT_texture_filter_anisotropic') || gl.getExtension('MOZ_EXT_texture_filter_anisotropic')
            if (ext) {
                var anisotropy = gl.getParameter(ext.MAX_TEXTURE_MAX_ANISOTROPY_EXT)
                if (anisotropy === 0) {
                    anisotropy = 2
                }
                return anisotropy
            } else {
                return null
            }
        }

        gl = getWebglCanvas()
        if (!gl) {
            return null
        }
        // WebGL fingerprinting is a combination of techniques, found in MaxMind antifraud script & Augur fingerprinting.
        // First it draws a gradient object with shaders and convers the image to the Base64 string.
        // Then it enumerates all WebGL extensions & capabilities and appends them to the Base64 string, resulting in a huge WebGL string, potentially very unique on each device
        // Since iOS supports webgl starting from version 8.1 and 8.1 runs on several graphics chips, the results may be different across ios devices, but we need to verify it.
        var result = []
        var vShaderTemplate = 'attribute vec2 attrVertex;varying vec2 varyinTexCoordinate;uniform vec2 uniformOffset;void main(){varyinTexCoordinate=attrVertex+uniformOffset;gl_Position=vec4(attrVertex,0,1);}'
        var fShaderTemplate = 'precision mediump float;varying vec2 varyinTexCoordinate;void main() {gl_FragColor=vec4(varyinTexCoordinate,0,1);}'
        var vertexPosBuffer = gl.createBuffer()
        gl.bindBuffer(gl.ARRAY_BUFFER, vertexPosBuffer)
        var vertices = new Float32Array([-0.2, -0.9, 0, 0.4, -0.26, 0, 0, 0.732134444, 0])
        gl.bufferData(gl.ARRAY_BUFFER, vertices, gl.STATIC_DRAW)
        vertexPosBuffer.itemSize = 3
        vertexPosBuffer.numItems = 3
        var program = gl.createProgram()
        var vshader = gl.createShader(gl.VERTEX_SHADER)
        gl.shaderSource(vshader, vShaderTemplate)
        gl.compileShader(vshader)
        var fshader = gl.createShader(gl.FRAGMENT_SHADER)
        gl.shaderSource(fshader, fShaderTemplate)
        gl.compileShader(fshader)
        gl.attachShader(program, vshader)
        gl.attachShader(program, fshader)
        gl.linkProgram(program)
        gl.useProgram(program)
        program.vertexPosAttrib = gl.getAttribLocation(program, 'attrVertex')
        program.offsetUniform = gl.getUniformLocation(program, 'uniformOffset')
        gl.enableVertexAttribArray(program.vertexPosArray)
        gl.vertexAttribPointer(program.vertexPosAttrib, vertexPosBuffer.itemSize, gl.FLOAT, !1, 0, 0)
        gl.uniform2f(program.offsetUniform, 1, 1)
        gl.drawArrays(gl.TRIANGLE_STRIP, 0, vertexPosBuffer.numItems)
        try {
            result.push(gl.canvas.toDataURL())
        } catch (e) {
            /* .toDataURL may be absent or broken (blocked by extension) */
        }
        result.push('extensions:' + (gl.getSupportedExtensions() || []).join(';'))
        result.push('webgl aliased line width range:' + fa2s(gl.getParameter(gl.ALIASED_LINE_WIDTH_RANGE)))
        result.push('webgl aliased point size range:' + fa2s(gl.getParameter(gl.ALIASED_POINT_SIZE_RANGE)))
        result.push('webgl alpha bits:' + gl.getParameter(gl.ALPHA_BITS))
        result.push('webgl antialiasing:' + (gl.getContextAttributes().antialias ? 'yes' : 'no'))
        result.push('webgl blue bits:' + gl.getParameter(gl.BLUE_BITS))
        result.push('webgl depth bits:' + gl.getParameter(gl.DEPTH_BITS))
        result.push('webgl green bits:' + gl.getParameter(gl.GREEN_BITS))
        result.push('webgl max anisotropy:' + maxAnisotropy(gl))
        result.push('webgl max combined texture image units:' + gl.getParameter(gl.MAX_COMBINED_TEXTURE_IMAGE_UNITS))
        result.push('webgl max cube map texture size:' + gl.getParameter(gl.MAX_CUBE_MAP_TEXTURE_SIZE))
        result.push('webgl max fragment uniform vectors:' + gl.getParameter(gl.MAX_FRAGMENT_UNIFORM_VECTORS))
        result.push('webgl max render buffer size:' + gl.getParameter(gl.MAX_RENDERBUFFER_SIZE))
        result.push('webgl max texture image units:' + gl.getParameter(gl.MAX_TEXTURE_IMAGE_UNITS))
        result.push('webgl max texture size:' + gl.getParameter(gl.MAX_TEXTURE_SIZE))
        result.push('webgl max varying vectors:' + gl.getParameter(gl.MAX_VARYING_VECTORS))
        result.push('webgl max vertex attribs:' + gl.getParameter(gl.MAX_VERTEX_ATTRIBS))
        result.push('webgl max vertex texture image units:' + gl.getParameter(gl.MAX_VERTEX_TEXTURE_IMAGE_UNITS))
        result.push('webgl max vertex uniform vectors:' + gl.getParameter(gl.MAX_VERTEX_UNIFORM_VECTORS))
        result.push('webgl max viewport dims:' + fa2s(gl.getParameter(gl.MAX_VIEWPORT_DIMS)))
        result.push('webgl red bits:' + gl.getParameter(gl.RED_BITS))
        result.push('webgl renderer:' + gl.getParameter(gl.RENDERER))
        result.push('webgl shading language version:' + gl.getParameter(gl.SHADING_LANGUAGE_VERSION))
        result.push('webgl stencil bits:' + gl.getParameter(gl.STENCIL_BITS))
        result.push('webgl vendor:' + gl.getParameter(gl.VENDOR))
        result.push('webgl version:' + gl.getParameter(gl.VERSION))

        try {
            // Add the unmasked vendor and unmasked renderer if the debug_renderer_info extension is available
            var extensionDebugRendererInfo = gl.getExtension('WEBGL_debug_renderer_info')
            if (extensionDebugRendererInfo) {
                result.push('webgl unmasked vendor:' + gl.getParameter(extensionDebugRendererInfo.UNMASKED_VENDOR_WEBGL))
                result.push('webgl unmasked renderer:' + gl.getParameter(extensionDebugRendererInfo.UNMASKED_RENDERER_WEBGL))
            }
        } catch (e) { /* squelch */
        }

        if (!gl.getShaderPrecisionFormat) {
            return result
        }

        each(['FLOAT', 'INT'], function (numType) {
            each(['VERTEX', 'FRAGMENT'], function (shader) {
                each(['HIGH', 'MEDIUM', 'LOW'], function (numSize) {
                    each(['precision', 'rangeMin', 'rangeMax'], function (key) {
                        var format = gl.getShaderPrecisionFormat(gl[shader + '_SHADER'], gl[numSize + '_' + numType])[key]
                        if (key !== 'precision') {
                            key = 'precision ' + key
                        }
                        var line = ['webgl ', shader.toLowerCase(), ' shader ', numSize.toLowerCase(), ' ', numType.toLowerCase(), ' ', key, ':', format].join('')
                        result.push(line)
                    })
                })
            })
        })
        return result
    }
    var getWebglVendorAndRenderer = function () {
        /* This a subset of the WebGL fingerprint with a lot of entropy, while being reasonably browser-independent */
        try {
            var glContext = getWebglCanvas()
            var extensionDebugRendererInfo = glContext.getExtension('WEBGL_debug_renderer_info')
            return glContext.getParameter(extensionDebugRendererInfo.UNMASKED_VENDOR_WEBGL) + '~' + glContext.getParameter(extensionDebugRendererInfo.UNMASKED_RENDERER_WEBGL)
        } catch (e) {
            return null
        }
    }
    var getAdBlock = function () {
        var ads = document.createElement('div')
        ads.innerHTML = '&nbsp;'
        ads.className = 'adsbox'
        var result = false
        try {
            // body may not exist, that's why we need try/catch
            document.body.appendChild(ads)
            result = document.getElementsByClassName('adsbox')[0].offsetHeight === 0
            document.body.removeChild(ads)
        } catch (e) {
            result = false
        }
        return result
    }
    var getHasLiedLanguages = function () {
        // We check if navigator.language is equal to the first language of navigator.languages
        // navigator.languages is undefined on IE11 (and potentially older IEs)
        if (typeof navigator.languages !== 'undefined') {
            try {
                var firstLanguages = navigator.languages[0].substr(0, 2)
                if (firstLanguages !== navigator.language.substr(0, 2)) {
                    return true
                }
            } catch (err) {
                return true
            }
        }
        return false
    }
    var getHasLiedResolution = function () {
        return window.screen.width < window.screen.availWidth || window.screen.height < window.screen.availHeight
    }
    var getHasLiedOs = function () {
        var userAgent = navigator.userAgent.toLowerCase()
        var oscpu = navigator.oscpu
        var platform = navigator.platform.toLowerCase()
        var os
        // We extract the OS from the user agent (respect the order of the if else if statement)
        if (userAgent.indexOf('windows phone') >= 0) {
            os = 'Windows Phone'
        } else if (userAgent.indexOf('win') >= 0) {
            os = 'Windows'
        } else if (userAgent.indexOf('android') >= 0) {
            os = 'Android'
        } else if (userAgent.indexOf('linux') >= 0 || userAgent.indexOf('cros') >= 0) {
            os = 'Linux'
        } else if (userAgent.indexOf('iphone') >= 0 || userAgent.indexOf('ipad') >= 0) {
            os = 'iOS'
        } else if (userAgent.indexOf('mac') >= 0) {
            os = 'Mac'
        } else {
            os = 'Other'
        }
        // We detect if the person uses a mobile device
        var mobileDevice = (('ontouchstart' in window) ||
            (navigator.maxTouchPoints > 0) ||
            (navigator.msMaxTouchPoints > 0))

        if (mobileDevice && os !== 'Windows Phone' && os !== 'Android' && os !== 'iOS' && os !== 'Other') {
            return true
        }

        // We compare oscpu with the OS extracted from the UA
        if (typeof oscpu !== 'undefined') {
            oscpu = oscpu.toLowerCase()
            if (oscpu.indexOf('win') >= 0 && os !== 'Windows' && os !== 'Windows Phone') {
                return true
            } else if (oscpu.indexOf('linux') >= 0 && os !== 'Linux' && os !== 'Android') {
                return true
            } else if (oscpu.indexOf('mac') >= 0 && os !== 'Mac' && os !== 'iOS') {
                return true
            } else if ((oscpu.indexOf('win') === -1 && oscpu.indexOf('linux') === -1 && oscpu.indexOf('mac') === -1) !== (os === 'Other')) {
                return true
            }
        }

        // We compare platform with the OS extracted from the UA
        if (platform.indexOf('win') >= 0 && os !== 'Windows' && os !== 'Windows Phone') {
            return true
        } else if ((platform.indexOf('linux') >= 0 || platform.indexOf('android') >= 0 || platform.indexOf('pike') >= 0) && os !== 'Linux' && os !== 'Android') {
            return true
        } else if ((platform.indexOf('mac') >= 0 || platform.indexOf('ipad') >= 0 || platform.indexOf('ipod') >= 0 || platform.indexOf('iphone') >= 0) && os !== 'Mac' && os !== 'iOS') {
            return true
        } else {
            var platformIsOther = platform.indexOf('win') < 0 &&
                platform.indexOf('linux') < 0 &&
                platform.indexOf('mac') < 0 &&
                platform.indexOf('iphone') < 0 &&
                platform.indexOf('ipad') < 0
            if (platformIsOther !== (os === 'Other')) {
                return true
            }
        }

        return typeof navigator.plugins === 'undefined' && os !== 'Windows' && os !== 'Windows Phone'
    }
    var getHasLiedBrowser = function () {
        var userAgent = navigator.userAgent.toLowerCase()
        var productSub = navigator.productSub

        // we extract the browser from the user agent (respect the order of the tests)
        var browser
        if (userAgent.indexOf('firefox') >= 0) {
            browser = 'Firefox'
        } else if (userAgent.indexOf('opera') >= 0 || userAgent.indexOf('opr') >= 0) {
            browser = 'Opera'
        } else if (userAgent.indexOf('chrome') >= 0) {
            browser = 'Chrome'
        } else if (userAgent.indexOf('safari') >= 0) {
            browser = 'Safari'
        } else if (userAgent.indexOf('trident') >= 0) {
            browser = 'Internet Explorer'
        } else {
            browser = 'Other'
        }

        if ((browser === 'Chrome' || browser === 'Safari' || browser === 'Opera') && productSub !== '20030107') {
            return true
        }

        // eslint-disable-next-line no-eval
        var tempRes = eval.toString().length
        if (tempRes === 37 && browser !== 'Safari' && browser !== 'Firefox' && browser !== 'Other') {
            return true
        } else if (tempRes === 39 && browser !== 'Internet Explorer' && browser !== 'Other') {
            return true
        } else if (tempRes === 33 && browser !== 'Chrome' && browser !== 'Opera' && browser !== 'Other') {
            return true
        }

        // We create an error to see how it is handled
        var errFirefox
        try {
            // eslint-disable-next-line no-throw-literal
            throw 'a'
        } catch (err) {
            try {
                err.toSource()
                errFirefox = true
            } catch (errOfErr) {
                errFirefox = false
            }
        }
        return errFirefox && browser !== 'Firefox' && browser !== 'Other'
    }
    var isCanvasSupported = function () {
        var elem = document.createElement('canvas')
        return !!(elem.getContext && elem.getContext('2d'))
    }
    var isWebGlSupported = function () {
        // code taken from Modernizr
        if (!isCanvasSupported()) {
            return false
        }

        var glContext = getWebglCanvas()
        return !!window.WebGLRenderingContext && !!glContext
    }
    var isIE = function () {
        if (navigator.appName === 'Microsoft Internet Explorer') {
            return true
        } else if (navigator.appName === 'Netscape' && /Trident/.test(navigator.userAgent)) { // IE 11
            return true
        }
        return false
    }
    var hasSwfObjectLoaded = function () {
        return typeof window.swfobject !== 'undefined'
    }
    var hasMinFlashInstalled = function () {
        return window.swfobject.hasFlashPlayerVersion('9.0.0')
    }
    var addFlashDivNode = function (options) {
        var node = document.createElement('div')
        node.setAttribute('id', options.fonts.swfContainerId)
        document.body.appendChild(node)
    }
    var loadSwfAndDetectFonts = function (done, options) {
        var hiddenCallback = '___fp_swf_loaded'
        window[hiddenCallback] = function (fonts) {
            done(fonts)
        }
        var id = options.fonts.swfContainerId
        addFlashDivNode()
        var flashvars = {onReady: hiddenCallback}
        var flashparams = {allowScriptAccess: 'always', menu: 'false'}
        window.swfobject.embedSWF(options.fonts.swfPath, id, '1', '1', '9.0.0', false, flashvars, flashparams, {})
    }
    var getWebglCanvas = function () {
        var canvas = document.createElement('canvas')
        var gl = null
        try {
            gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl')
        } catch (e) { /* squelch */
        }
        if (!gl) {
            gl = null
        }
        return gl
    }

    var components = [
        {key: 'userAgent', getData: UserAgent},
        {key: 'webdriver', getData: webdriver},
        {key: 'language', getData: languageKey},
        {key: 'colorDepth', getData: colorDepthKey},
        {key: 'deviceMemory', getData: deviceMemoryKey},
        {key: 'pixelRatio', getData: pixelRatioKey},
        {key: 'hardwareConcurrency', getData: hardwareConcurrencyKey},
        {key: 'screenResolution', getData: screenResolutionKey},
        {key: 'availableScreenResolution', getData: availableScreenResolutionKey},
        {key: 'timezoneOffset', getData: timezoneOffset},
        {key: 'timezone', getData: timezone},
        {key: 'sessionStorage', getData: sessionStorageKey},
        {key: 'localStorage', getData: localStorageKey},
        {key: 'indexedDb', getData: indexedDbKey},
        {key: 'addBehavior', getData: addBehaviorKey},
        {key: 'openDatabase', getData: openDatabaseKey},
        {key: 'cpuClass', getData: cpuClassKey},
        {key: 'platform', getData: platformKey},
        {key: 'doNotTrack', getData: doNotTrackKey},
        {key: 'plugins', getData: pluginsComponent},
        {key: 'canvas', getData: canvasKey},
        {key: 'webgl', getData: webglKey},
        {key: 'webglVendorAndRenderer', getData: webglVendorAndRendererKey},
        {key: 'adBlock', getData: adBlockKey},
        {key: 'hasLiedLanguages', getData: hasLiedLanguagesKey},
        {key: 'hasLiedResolution', getData: hasLiedResolutionKey},
        {key: 'hasLiedOs', getData: hasLiedOsKey},
        {key: 'hasLiedBrowser', getData: hasLiedBrowserKey},
        {key: 'touchSupport', getData: touchSupportKey},
        {key: 'fonts', getData: jsFontsKey, pauseBefore: true},
        {key: 'fontsFlash', getData: flashFontsKey, pauseBefore: true},
        {key: 'audio', getData: audioKey},
        {key: 'enumerateDevices', getData: enumerateDevicesKey}
    ]

    var Fingerprint2 = function (options) {
        throw new Error("'new Fingerprint()' is deprecated, see https://github.com/Valve/fingerprintjs2#upgrade-guide-from-182-to-200")
    }

    Fingerprint2.get = function (options, callback) {
        if (!callback) {
            callback = options
            options = {}
        } else if (!options) {
            options = {}
        }
        extendSoft(options, defaultOptions)
        options.components = options.extraComponents.concat(components)

        var keys = {
            data: [],
            addPreprocessedComponent: function (key, value) {
                if (typeof options.preprocessor === 'function') {
                    value = options.preprocessor(key, value)
                }
                keys.data.push({key: key, value: value})
            }
        }

        var i = -1
        var chainComponents = function (alreadyWaited) {
            i += 1
            if (i >= options.components.length) { // on finish
                callback(keys.data)
                return
            }
            var component = options.components[i]

            if (options.excludes[component.key]) {
                chainComponents(false) // skip
                return
            }

            if (!alreadyWaited && component.pauseBefore) {
                i -= 1
                setTimeout(function () {
                    chainComponents(true)
                }, 1)
                return
            }

            try {
                component.getData(function (value) {
                    keys.addPreprocessedComponent(component.key, value)
                    chainComponents(false)
                }, options)
            } catch (error) {
                // main body error
                keys.addPreprocessedComponent(component.key, String(error))
                chainComponents(false)
            }
        }

        chainComponents(false)
    }

    Fingerprint2.getPromise = function (options) {
        return new Promise(function (resolve, reject) {
            Fingerprint2.get(options, resolve)
        })
    }

    Fingerprint2.getV18 = function (options, callback) {
        if (callback == null) {
            callback = options
            options = {}
        }
        return Fingerprint2.get(options, function (components) {
            var newComponents = []
            for (var i = 0; i < components.length; i++) {
                var component = components[i]
                if (component.value === (options.NOT_AVAILABLE || 'not available')) {
                    newComponents.push({key: component.key, value: 'unknown'})
                } else if (component.key === 'plugins') {
                    newComponents.push({
                        key: 'plugins',
                        value: map(component.value, function (p) {
                            var mimeTypes = map(p[2], function (mt) {
                                if (mt.join) {
                                    return mt.join('~')
                                }
                                return mt
                            }).join(',')
                            return [p[0], p[1], mimeTypes].join('::')
                        })
                    })
                } else if (['canvas', 'webgl'].indexOf(component.key) !== -1) {
                    newComponents.push({key: component.key, value: component.value.join('~')})
                } else if (['sessionStorage', 'localStorage', 'indexedDb', 'addBehavior', 'openDatabase'].indexOf(component.key) !== -1) {
                    if (component.value) {
                        newComponents.push({key: component.key, value: 1})
                    } else {
                        // skip
                        continue
                    }
                } else {
                    if (component.value) {
                        newComponents.push(component.value.join ? {
                            key: component.key,
                            value: component.value.join(';')
                        } : component)
                    } else {
                        newComponents.push({key: component.key, value: component.value})
                    }
                }
            }
            var murmur = x64hash128(map(newComponents, function (component) {
                return component.value
            }).join('~~~'), 31)
            callback(murmur, newComponents)
        })
    }

    Fingerprint2.x64hash128 = x64hash128
    Fingerprint2.VERSION = '2.1.0'
    return Fingerprint2
})