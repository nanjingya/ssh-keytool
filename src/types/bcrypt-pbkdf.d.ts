declare module 'bcrypt-pbkdf' {
  function pbkdf(
    pass: Buffer | string,
    passlen: number,
    salt: Buffer | string,
    saltlen: number,
    key: Buffer,
    keylen: number,
    rounds: number,
  ): void

  function pbkdf_async(
    pass: Buffer | string,
    passlen: number,
    salt: Buffer | string,
    saltlen: number,
    key: Buffer,
    keylen: number,
    rounds: number,
    cb: (err: Error | null) => void,
  ): void
}
