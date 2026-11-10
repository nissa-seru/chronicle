- `getStateJson`, `getStateJsonAt`, `getStateItemJson` and
  `getStateItemsJson` now give back a state's stored JSON as `JSON.parse`
  reads it, where the conversion to JavaScript assigned each object key
  and serde_json read the numbers. Bytes that serde_json doesn't read as
  one JSON value still throw `Deserialization`, such as `1e400` or a lone
  surrogate escape.
  - An object's own `__proto__` key was lost, or, with an object under it,
    became the read object's prototype. It now reads back as an own key, at
    any depth.
  - An object key holding NUL threw `GenericFailure` ("nul byte found"). It
    now reads back.
  - An integer of 2^53 or more in size, up to 64 bits, read as a BigInt. It
    now reads as the nearest Number, as `JSON.parse` reads it. `getState`
    and `getStateAt` give the bytes, with every digit.
- serde_json now parses each decimal to the nearest double, as
  `JSON.parse` does (its `float_roundtrip` feature). It rounded more than
  once, so some decimals came back one unit off in their last digit, such
  as `9.498154036532778e-76` as `9.498154036532777e-76`: in the JSON
  reads, and in an append-log state's bytes, which the store rebuilds
  through serde_json. A snapshot of an append-log state stored them so,
  and a later snapshot could move a stored decimal again.
  - Decimals now keep the value they were written with, in every read and
    in `getState`'s bytes, and snapshots no longer move them. The bytes
    hold the value as serde_json writes it, so `1e2` comes back as
    `100.0`.
  - A store written by an earlier release keeps the digits its snapshots
    stored: a decimal a snapshot holds reads back as that snapshot wrote
    it. A decimal not yet in a snapshot reads back with the value it was
    written with.
