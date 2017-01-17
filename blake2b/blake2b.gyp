{
  'targets': [
    {
      'target_name': 'blake2b_gtest',
      'type': 'executable',
      'include_dirs': [
        'include/',
      ],
      'sources': [
        'src/blake2b.c',
        'src/blake2b_unittests.cc',
      ],
   }
      ],
}
