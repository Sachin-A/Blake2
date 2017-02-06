{
  'targets': [
    {
      'target_name': 'argon2_gtest',
      'type': 'executable',
      'include_dirs': [
      	'include/',
      ],
      'sources': [
        'src/blake2b.c',
        'src/argon2.c',
        'src/argon2-core.c',
        'src/argon2-ref.c',
        'src/argon2_unittests.cc',     
      ],
       'conditions': [
        ['OS == "linux"', {
        	'ldflags': [
              '-pthread',
              '-lgtest',
              '-g',
            ],
          }],
      ],
   	}
  ],
}