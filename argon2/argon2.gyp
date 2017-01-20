{
  'targets': [
    {
      'target_name': 'argon2',
      'type': 'executable',
      'include_dirs': [
      	'include/',
      ],
      'sources': [
        'src/blake2b.c',
        'src/argon2.c',
        'src/argon2-core.c',
        'src/argon2-ref.c',
        'src/test.c',     
      ],
       'conditions': [
        ['OS == "linux"', {
        	'ldflags': [
              '-pthread',
              '-g',
            ],
          }],
      ],
   	}
  ],
}