/* This file is created by make_test_messages.sh from CBOR diag files */
const unsigned char aead_in_error[] = {
  0xd8, 0x60, 0x84, 0x43, 0xa1, 0x01, 0x03, 0xa1,
  0x05, 0x4c, 0x02, 0xd1, 0xf7, 0xe6, 0xf2, 0x6c,
  0x43, 0xd4, 0x86, 0x8d, 0x87, 0xce, 0x58, 0x24,
  0x25, 0x6b, 0x74, 0x8d, 0xeb, 0x64, 0x71, 0x31,
  0xc1, 0x2a, 0x10, 0xac, 0x26, 0x1d, 0xa0, 0x62,
  0x8e, 0x42, 0x04, 0x92, 0xa3, 0x6f, 0x3d, 0xed,
  0x86, 0x42, 0xb4, 0xb6, 0xfa, 0x1e, 0xb1, 0x5d,
  0xce, 0xc8, 0x0a, 0x0e, 0x81, 0x83, 0x44, 0xa1,
  0x01, 0x38, 0x1c, 0xa2, 0x20, 0xa4, 0x01, 0x02,
  0x20, 0x01, 0x21, 0x58, 0x20, 0xe1, 0x2c, 0x93,
  0x8b, 0x18, 0x22, 0x58, 0xc9, 0xd4, 0x47, 0xd4,
  0x18, 0x21, 0x71, 0x52, 0x61, 0xae, 0x99, 0xad,
  0x77, 0xd2, 0x41, 0x94, 0x3f, 0x4a, 0x12, 0xff,
  0x20, 0xdd, 0x3c, 0xe4, 0x00, 0x22, 0x58, 0x20,
  0x48, 0xb0, 0x58, 0x89, 0x03, 0x36, 0x57, 0x33,
  0xb9, 0x8d, 0x38, 0x8c, 0x61, 0x36, 0xc0, 0x4b,
  0x7f, 0xfd, 0x1a, 0x77, 0x0c, 0xd2, 0x61, 0x11,
  0x89, 0xee, 0x84, 0xe9, 0x94, 0x1a, 0x7e, 0x26,
  0x04, 0x58, 0x24, 0x6d, 0x65, 0x72, 0x69, 0x61,
  0x64, 0x6f, 0x63, 0x2e, 0x62, 0x72, 0x61, 0x6e,
  0x64, 0x79, 0x62, 0x75, 0x63, 0x6b, 0x40, 0x62,
  0x75, 0x63, 0x6b, 0x6c, 0x61, 0x6e, 0x64, 0x2e,
  0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x58,
  0x28, 0x50, 0x8f, 0xad, 0x30, 0xa1, 0xa9, 0x5d,
  0x13, 0x80, 0xb5, 0x16, 0x7d, 0x03, 0x27, 0x99,
  0xc7, 0x24, 0x77, 0xab, 0x60, 0x25, 0x8a, 0xbf,
  0xb7, 0x1c, 0x7a, 0xb6, 0x03, 0xa4, 0x89, 0x0e,
  0xf4, 0x4f, 0x13, 0x63, 0xed, 0x9f, 0x56, 0x9e,
  0x85
};
const unsigned int aead_in_error_len = 225;
const unsigned char cose_encrypt_junk_recipient[] = {
  0xd8, 0x60, 0x84, 0x43, 0xa1, 0x01, 0x03, 0xa1,
  0x05, 0x4c, 0x02, 0xd1, 0xf7, 0xe6, 0xf2, 0x6c,
  0x43, 0xd4, 0x86, 0x8d, 0x87, 0xce, 0x58, 0x24,
  0x25, 0x6b, 0x74, 0x8d, 0xeb, 0x64, 0x71, 0x31,
  0xc1, 0x2a, 0x10, 0xac, 0x26, 0x1d, 0xa0, 0x62,
  0x8e, 0x42, 0x04, 0x92, 0xa3, 0x6f, 0x3d, 0xed,
  0x86, 0x42, 0xb4, 0xb6, 0xfa, 0x1e, 0xb1, 0x5d,
  0xce, 0xc8, 0x0a, 0x0f, 0x82, 0x78, 0x18, 0x6a,
  0x75, 0x6e, 0x6b, 0x20, 0x69, 0x6e, 0x20, 0x72,
  0x65, 0x63, 0x69, 0x70, 0x69, 0x65, 0x6e, 0x74,
  0x73, 0x20, 0x61, 0x72, 0x72, 0x61, 0x79, 0x83,
  0x44, 0xa1, 0x01, 0x38, 0x1c, 0xa2, 0x20, 0xa4,
  0x01, 0x02, 0x20, 0x01, 0x21, 0x58, 0x20, 0xe1,
  0x2c, 0x93, 0x8b, 0x18, 0x22, 0x58, 0xc9, 0xd4,
  0x47, 0xd4, 0x18, 0x21, 0x71, 0x52, 0x61, 0xae,
  0x99, 0xad, 0x77, 0xd2, 0x41, 0x94, 0x3f, 0x4a,
  0x12, 0xff, 0x20, 0xdd, 0x3c, 0xe4, 0x00, 0x22,
  0x58, 0x20, 0x48, 0xb0, 0x58, 0x89, 0x03, 0x36,
  0x57, 0x33, 0xb9, 0x8d, 0x38, 0x8c, 0x61, 0x36,
  0xc0, 0x4b, 0x7f, 0xfd, 0x1a, 0x77, 0x0c, 0xd2,
  0x61, 0x11, 0x89, 0xee, 0x84, 0xe9, 0x94, 0x1a,
  0x7e, 0x26, 0x04, 0x58, 0x24, 0x6d, 0x65, 0x72,
  0x69, 0x61, 0x64, 0x6f, 0x63, 0x2e, 0x62, 0x72,
  0x61, 0x6e, 0x64, 0x79, 0x62, 0x75, 0x63, 0x6b,
  0x40, 0x62, 0x75, 0x63, 0x6b, 0x6c, 0x61, 0x6e,
  0x64, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
  0x65, 0x58, 0x28, 0x50, 0x8f, 0xad, 0x30, 0xa1,
  0xa9, 0x5d, 0x13, 0x80, 0xb5, 0x16, 0x7d, 0x03,
  0x27, 0x99, 0xc7, 0x24, 0x77, 0xab, 0x60, 0x25,
  0x8a, 0xbf, 0xb7, 0x1c, 0x7a, 0xb6, 0x03, 0xa4,
  0x89, 0x0e, 0xf4, 0x4f, 0x13, 0x63, 0xed, 0x9f,
  0x56, 0x9e, 0x85
};
const unsigned int cose_encrypt_junk_recipient_len = 251;
const unsigned char cose_encrypt_p256_wrap_128[] = {
  0xd8, 0x60, 0x84, 0x43, 0xa1, 0x01, 0x03, 0xa1,
  0x05, 0x4c, 0x02, 0xd1, 0xf7, 0xe6, 0xf2, 0x6c,
  0x43, 0xd4, 0x86, 0x8d, 0x87, 0xce, 0x58, 0x24,
  0x25, 0x6b, 0x74, 0x8d, 0xeb, 0x64, 0x71, 0x31,
  0xc1, 0x2a, 0x10, 0xac, 0x26, 0x1d, 0xa0, 0x62,
  0x8e, 0x42, 0x04, 0x92, 0xa3, 0x6f, 0x3d, 0xed,
  0x86, 0x42, 0xb4, 0xb6, 0xfa, 0x1e, 0xb1, 0x5d,
  0xce, 0xc8, 0x0a, 0x0f, 0x81, 0x83, 0x44, 0xa1,
  0x01, 0x38, 0x1c, 0xa2, 0x20, 0xa4, 0x01, 0x02,
  0x20, 0x01, 0x21, 0x58, 0x20, 0xe1, 0x2c, 0x93,
  0x8b, 0x18, 0x22, 0x58, 0xc9, 0xd4, 0x47, 0xd4,
  0x18, 0x21, 0x71, 0x52, 0x61, 0xae, 0x99, 0xad,
  0x77, 0xd2, 0x41, 0x94, 0x3f, 0x4a, 0x12, 0xff,
  0x20, 0xdd, 0x3c, 0xe4, 0x00, 0x22, 0x58, 0x20,
  0x48, 0xb0, 0x58, 0x89, 0x03, 0x36, 0x57, 0x33,
  0xb9, 0x8d, 0x38, 0x8c, 0x61, 0x36, 0xc0, 0x4b,
  0x7f, 0xfd, 0x1a, 0x77, 0x0c, 0xd2, 0x61, 0x11,
  0x89, 0xee, 0x84, 0xe9, 0x94, 0x1a, 0x7e, 0x26,
  0x04, 0x58, 0x24, 0x6d, 0x65, 0x72, 0x69, 0x61,
  0x64, 0x6f, 0x63, 0x2e, 0x62, 0x72, 0x61, 0x6e,
  0x64, 0x79, 0x62, 0x75, 0x63, 0x6b, 0x40, 0x62,
  0x75, 0x63, 0x6b, 0x6c, 0x61, 0x6e, 0x64, 0x2e,
  0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x58,
  0x28, 0x50, 0x8f, 0xad, 0x30, 0xa1, 0xa9, 0x5d,
  0x13, 0x80, 0xb5, 0x16, 0x7d, 0x03, 0x27, 0x99,
  0xc7, 0x24, 0x77, 0xab, 0x60, 0x25, 0x8a, 0xbf,
  0xb7, 0x1c, 0x7a, 0xb6, 0x03, 0xa4, 0x89, 0x0e,
  0xf4, 0x4f, 0x13, 0x63, 0xed, 0x9f, 0x56, 0x9e,
  0x85
};
const unsigned int cose_encrypt_p256_wrap_128_len = 225;
const unsigned char cose_encrypt_p256_wrap_aescbc[] = {
  0xd8, 0x60, 0x84, 0x40, 0xa2, 0x01, 0x39, 0xff,
  0xfa, 0x05, 0x50, 0x82, 0x62, 0xa8, 0xd7, 0x20,
  0x40, 0xa5, 0xe0, 0x9a, 0x31, 0x45, 0x86, 0x39,
  0x5d, 0x57, 0x50, 0x58, 0x20, 0xb6, 0x0e, 0xc3,
  0xc9, 0xa1, 0x66, 0xd8, 0xee, 0xfd, 0xae, 0xa5,
  0x98, 0xfa, 0xb1, 0xce, 0xbb, 0x7f, 0x0d, 0x5d,
  0xdf, 0x22, 0x37, 0xf1, 0x3a, 0x03, 0xa9, 0x13,
  0x64, 0x59, 0x49, 0x83, 0xfe, 0x81, 0x83, 0x40,
  0xa1, 0x01, 0x22, 0x58, 0x18, 0xd2, 0x1a, 0x60,
  0xf7, 0xf6, 0x7b, 0xa8, 0x66, 0xf1, 0x5b, 0xe2,
  0x7c, 0x98, 0x38, 0x81, 0xaa, 0x47, 0xdf, 0x15,
  0xae, 0x69, 0x25, 0xa0, 0xd1
};
const unsigned int cose_encrypt_p256_wrap_aescbc_len = 93;
const unsigned char cose_encrypt_p256_wrap_aesctr[] = {
  0xd8, 0x60, 0x84, 0x40, 0xa2, 0x01, 0x39, 0xff,
  0xfd, 0x05, 0x50, 0x77, 0xd3, 0x52, 0x42, 0xa1,
  0x91, 0xe9, 0xf9, 0xfd, 0x26, 0x10, 0x4a, 0xb3,
  0x08, 0x56, 0x4e, 0x53, 0x79, 0x3a, 0x61, 0x6a,
  0x56, 0x17, 0x48, 0x2b, 0xe7, 0x6f, 0x17, 0x07,
  0x78, 0x58, 0xb1, 0x48, 0x24, 0x15, 0x91, 0x81,
  0x83, 0x40, 0xa1, 0x01, 0x22, 0x58, 0x18, 0x31,
  0x6a, 0xda, 0x13, 0x00, 0x3f, 0xe7, 0xc6, 0x1a,
  0xd4, 0xea, 0x50, 0x35, 0x00, 0xb2, 0x85, 0xca,
  0xca, 0xde, 0x51, 0x07, 0xa8, 0xe2, 0x80
};
const unsigned int cose_encrypt_p256_wrap_aesctr_len = 79;
const unsigned char cose_recipients_map_instead_of_array[] = {
  0xd8, 0x60, 0x84, 0x43, 0xa1, 0x01, 0x03, 0xa1,
  0x05, 0x4c, 0x02, 0xd1, 0xf7, 0xe6, 0xf2, 0x6c,
  0x43, 0xd4, 0x86, 0x8d, 0x87, 0xce, 0x58, 0x24,
  0x25, 0x6b, 0x74, 0x8d, 0xeb, 0x64, 0x71, 0x31,
  0xc1, 0x2a, 0x10, 0xac, 0x26, 0x1d, 0xa0, 0x62,
  0x8e, 0x42, 0x04, 0x92, 0xa3, 0x6f, 0x3d, 0xed,
  0x86, 0x42, 0xb4, 0xb6, 0xfa, 0x1e, 0xb1, 0x5d,
  0xce, 0xc8, 0x0a, 0x0f, 0xa1, 0x65, 0x6c, 0x61,
  0x62, 0x65, 0x6c, 0x83, 0x44, 0xa1, 0x01, 0x38,
  0x1c, 0xa2, 0x20, 0xa4, 0x01, 0x02, 0x20, 0x01,
  0x21, 0x58, 0x20, 0xe1, 0x2c, 0x93, 0x8b, 0x18,
  0x22, 0x58, 0xc9, 0xd4, 0x47, 0xd4, 0x18, 0x21,
  0x71, 0x52, 0x61, 0xae, 0x99, 0xad, 0x77, 0xd2,
  0x41, 0x94, 0x3f, 0x4a, 0x12, 0xff, 0x20, 0xdd,
  0x3c, 0xe4, 0x00, 0x22, 0x58, 0x20, 0x48, 0xb0,
  0x58, 0x89, 0x03, 0x36, 0x57, 0x33, 0xb9, 0x8d,
  0x38, 0x8c, 0x61, 0x36, 0xc0, 0x4b, 0x7f, 0xfd,
  0x1a, 0x77, 0x0c, 0xd2, 0x61, 0x11, 0x89, 0xee,
  0x84, 0xe9, 0x94, 0x1a, 0x7e, 0x26, 0x04, 0x58,
  0x24, 0x6d, 0x65, 0x72, 0x69, 0x61, 0x64, 0x6f,
  0x63, 0x2e, 0x62, 0x72, 0x61, 0x6e, 0x64, 0x79,
  0x62, 0x75, 0x63, 0x6b, 0x40, 0x62, 0x75, 0x63,
  0x6b, 0x6c, 0x61, 0x6e, 0x64, 0x2e, 0x65, 0x78,
  0x61, 0x6d, 0x70, 0x6c, 0x65, 0x58, 0x28, 0x50,
  0x8f, 0xad, 0x30, 0xa1, 0xa9, 0x5d, 0x13, 0x80,
  0xb5, 0x16, 0x7d, 0x03, 0x27, 0x99, 0xc7, 0x24,
  0x77, 0xab, 0x60, 0x25, 0x8a, 0xbf, 0xb7, 0x1c,
  0x7a, 0xb6, 0x03, 0xa4, 0x89, 0x0e, 0xf4, 0x4f,
  0x13, 0x63, 0xed, 0x9f, 0x56, 0x9e, 0x85
};
const unsigned int cose_recipients_map_instead_of_array_len = 231;
const unsigned char tstr_ciphertext[] = {
  0xd8, 0x60, 0x84, 0x43, 0xa1, 0x01, 0x03, 0xa1,
  0x05, 0x4c, 0x02, 0xd1, 0xf7, 0xe6, 0xf2, 0x6c,
  0x43, 0xd4, 0x86, 0x8d, 0x87, 0xce, 0x78, 0x22,
  0x63, 0x69, 0x70, 0x68, 0x65, 0x72, 0x20, 0x74,
  0x65, 0x78, 0x74, 0x20, 0x74, 0x68, 0x61, 0x74,
  0x20, 0x69, 0x73, 0x20, 0x74, 0x73, 0x74, 0x72,
  0x2c, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x62, 0x73,
  0x74, 0x72, 0x81, 0x83, 0x44, 0xa1, 0x01, 0x38,
  0x1c, 0xa2, 0x20, 0xa4, 0x01, 0x02, 0x20, 0x01,
  0x21, 0x58, 0x20, 0xe1, 0x2c, 0x93, 0x8b, 0x18,
  0x22, 0x58, 0xc9, 0xd4, 0x47, 0xd4, 0x18, 0x21,
  0x71, 0x52, 0x61, 0xae, 0x99, 0xad, 0x77, 0xd2,
  0x41, 0x94, 0x3f, 0x4a, 0x12, 0xff, 0x20, 0xdd,
  0x3c, 0xe4, 0x00, 0x22, 0x58, 0x20, 0x48, 0xb0,
  0x58, 0x89, 0x03, 0x36, 0x57, 0x33, 0xb9, 0x8d,
  0x38, 0x8c, 0x61, 0x36, 0xc0, 0x4b, 0x7f, 0xfd,
  0x1a, 0x77, 0x0c, 0xd2, 0x61, 0x11, 0x89, 0xee,
  0x84, 0xe9, 0x94, 0x1a, 0x7e, 0x26, 0x04, 0x58,
  0x24, 0x6d, 0x65, 0x72, 0x69, 0x61, 0x64, 0x6f,
  0x63, 0x2e, 0x62, 0x72, 0x61, 0x6e, 0x64, 0x79,
  0x62, 0x75, 0x63, 0x6b, 0x40, 0x62, 0x75, 0x63,
  0x6b, 0x6c, 0x61, 0x6e, 0x64, 0x2e, 0x65, 0x78,
  0x61, 0x6d, 0x70, 0x6c, 0x65, 0x58, 0x28, 0x50,
  0x8f, 0xad, 0x30, 0xa1, 0xa9, 0x5d, 0x13, 0x80,
  0xb5, 0x16, 0x7d, 0x03, 0x27, 0x99, 0xc7, 0x24,
  0x77, 0xab, 0x60, 0x25, 0x8a, 0xbf, 0xb7, 0x1c,
  0x7a, 0xb6, 0x03, 0xa4, 0x89, 0x0e, 0xf4, 0x4f,
  0x13, 0x63, 0xed, 0x9f, 0x56, 0x9e, 0x85
};
const unsigned int tstr_ciphertext_len = 223;
const unsigned char unknown_symmetric_alg[] = {
  0xd8, 0x60, 0x84, 0x43, 0xa1, 0x01, 0x08, 0xa1,
  0x05, 0x4c, 0x02, 0xd1, 0xf7, 0xe6, 0xf2, 0x6c,
  0x43, 0xd4, 0x86, 0x8d, 0x87, 0xce, 0x58, 0x24,
  0x25, 0x6b, 0x74, 0x8d, 0xeb, 0x64, 0x71, 0x31,
  0xc1, 0x2a, 0x10, 0xac, 0x26, 0x1d, 0xa0, 0x62,
  0x8e, 0x42, 0x04, 0x92, 0xa3, 0x6f, 0x3d, 0xed,
  0x86, 0x42, 0xb4, 0xb6, 0xfa, 0x1e, 0xb1, 0x5d,
  0xce, 0xc8, 0x0a, 0x0f, 0x81, 0x83, 0x44, 0xa1,
  0x01, 0x38, 0x1c, 0xa2, 0x20, 0xa4, 0x01, 0x02,
  0x20, 0x01, 0x21, 0x58, 0x20, 0xe1, 0x2c, 0x93,
  0x8b, 0x18, 0x22, 0x58, 0xc9, 0xd4, 0x47, 0xd4,
  0x18, 0x21, 0x71, 0x52, 0x61, 0xae, 0x99, 0xad,
  0x77, 0xd2, 0x41, 0x94, 0x3f, 0x4a, 0x12, 0xff,
  0x20, 0xdd, 0x3c, 0xe4, 0x00, 0x22, 0x58, 0x20,
  0x48, 0xb0, 0x58, 0x89, 0x03, 0x36, 0x57, 0x33,
  0xb9, 0x8d, 0x38, 0x8c, 0x61, 0x36, 0xc0, 0x4b,
  0x7f, 0xfd, 0x1a, 0x77, 0x0c, 0xd2, 0x61, 0x11,
  0x89, 0xee, 0x84, 0xe9, 0x94, 0x1a, 0x7e, 0x26,
  0x04, 0x58, 0x24, 0x6d, 0x65, 0x72, 0x69, 0x61,
  0x64, 0x6f, 0x63, 0x2e, 0x62, 0x72, 0x61, 0x6e,
  0x64, 0x79, 0x62, 0x75, 0x63, 0x6b, 0x40, 0x62,
  0x75, 0x63, 0x6b, 0x6c, 0x61, 0x6e, 0x64, 0x2e,
  0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x58,
  0x28, 0x50, 0x8f, 0xad, 0x30, 0xa1, 0xa9, 0x5d,
  0x13, 0x80, 0xb5, 0x16, 0x7d, 0x03, 0x27, 0x99,
  0xc7, 0x24, 0x77, 0xab, 0x60, 0x25, 0x8a, 0xbf,
  0xb7, 0x1c, 0x7a, 0xb6, 0x03, 0xa4, 0x89, 0x0e,
  0xf4, 0x4f, 0x13, 0x63, 0xed, 0x9f, 0x56, 0x9e,
  0x85
};
const unsigned int unknown_symmetric_alg_len = 225;
const unsigned char unprot_headers_wrong_type[] = {
  0xd8, 0x60, 0x84, 0x43, 0xa1, 0x01, 0x03, 0x82,
  0x05, 0x4c, 0x02, 0xd1, 0xf7, 0xe6, 0xf2, 0x6c,
  0x43, 0xd4, 0x86, 0x8d, 0x87, 0xce, 0x58, 0x24,
  0x25, 0x6b, 0x74, 0x8d, 0xeb, 0x64, 0x71, 0x31,
  0xc1, 0x2a, 0x10, 0xac, 0x26, 0x1d, 0xa0, 0x62,
  0x8e, 0x42, 0x04, 0x92, 0xa3, 0x6f, 0x3d, 0xed,
  0x86, 0x42, 0xb4, 0xb6, 0xfa, 0x1e, 0xb1, 0x5d,
  0xce, 0xc8, 0x0a, 0x0f, 0x81, 0x83, 0x44, 0xa1,
  0x01, 0x38, 0x1c, 0xa2, 0x20, 0xa4, 0x01, 0x02,
  0x20, 0x01, 0x21, 0x58, 0x20, 0xe1, 0x2c, 0x93,
  0x8b, 0x18, 0x22, 0x58, 0xc9, 0xd4, 0x47, 0xd4,
  0x18, 0x21, 0x71, 0x52, 0x61, 0xae, 0x99, 0xad,
  0x77, 0xd2, 0x41, 0x94, 0x3f, 0x4a, 0x12, 0xff,
  0x20, 0xdd, 0x3c, 0xe4, 0x00, 0x22, 0x58, 0x20,
  0x48, 0xb0, 0x58, 0x89, 0x03, 0x36, 0x57, 0x33,
  0xb9, 0x8d, 0x38, 0x8c, 0x61, 0x36, 0xc0, 0x4b,
  0x7f, 0xfd, 0x1a, 0x77, 0x0c, 0xd2, 0x61, 0x11,
  0x89, 0xee, 0x84, 0xe9, 0x94, 0x1a, 0x7e, 0x26,
  0x04, 0x58, 0x24, 0x6d, 0x65, 0x72, 0x69, 0x61,
  0x64, 0x6f, 0x63, 0x2e, 0x62, 0x72, 0x61, 0x6e,
  0x64, 0x79, 0x62, 0x75, 0x63, 0x6b, 0x40, 0x62,
  0x75, 0x63, 0x6b, 0x6c, 0x61, 0x6e, 0x64, 0x2e,
  0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x58,
  0x28, 0x50, 0x8f, 0xad, 0x30, 0xa1, 0xa9, 0x5d,
  0x13, 0x80, 0xb5, 0x16, 0x7d, 0x03, 0x27, 0x99,
  0xc7, 0x24, 0x77, 0xab, 0x60, 0x25, 0x8a, 0xbf,
  0xb7, 0x1c, 0x7a, 0xb6, 0x03, 0xa4, 0x89, 0x0e,
  0xf4, 0x4f, 0x13, 0x63, 0xed, 0x9f, 0x56, 0x9e,
  0x85
};
const unsigned int unprot_headers_wrong_type_len = 225;
