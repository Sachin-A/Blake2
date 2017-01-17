{
  'targets': [
    {
      'target_name': 'argon2',
      'type': 'executable',
      'include_dirs': [
        'include/argon2.h',
        'include/argon2-core.h',
        'include/argon2-ref.h',
        '../blake2b/include/blake2b.h',
      ],
      'sources': [
        'src/argon2.c',
        'src/argon2-core.c',
        'src/argon2-ref.c',
        '../blake2b/src/blake2b.c',
      ],
   }
      ],
}