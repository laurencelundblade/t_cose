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
const unsigned char yy[] = {
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
const unsigned int yy_len = 225;
