# Third-party code

## TDLib (Boost Software License 1.0)

TDLib, https://github.com/tdlib/td, commit 4c6377a (2026-10-27).
Copyright Aliaksei Levin (levlam@telegram.org), Arseny Smirnov (arseny30@gmail.com) 2014-2026.
Distributed under the Boost Software License, Version 1.0; the full text is in `LICENSE_1_0.txt`.

What comes from it:

- `schema/telegram_api.tl` is TDLib's `td/generate/scheme/telegram_api.tl`, unchanged.
  `src/tg_schema.c` and `src/tg_schema.h` are generated from it by `tools/gen_tl.py`.
- These files are C ports of TDLib's `td/mtproto/` C++ code, cut down for small freestanding
  targets (no allocation, no globals, steppable heavy work). Each names the TDLib file and function
  it follows:
  - `src/tg_auth.c`, `src/tg_proto.h`: `Handshake.cpp`, `DhHandshake.cpp`, `RSA.cpp`, `Transport.cpp`
  - `src/tg_mtp.c`, `src/tg_mtp.h`: `KDF.cpp`, `Transport.cpp`
  - `src/tg_net.c`, `src/tg_net.h`: `TcpTransport.cpp` (intermediate transport)
  - `src/tg_session.c`, `src/tg_session.h`: `AuthData.cpp`, `AuthData.h`, `SessionConnection.cpp`
- `src/tg_keys.h` holds Telegram's public server RSA keys (production and test) and the DH prime,
  as TDLib lists them; `src/tg_client.c` uses TDLib's default DC address list.

The TDLib-derived files are distributed under the Boost licence; changes made to them here are
also available under the MIT licence in `LICENSE`.

## puff.c (zlib licence)

`src/tg_inflate.c` and `src/tg_inflate.h` are altered from `contrib/puff/puff.c` (version 2.3) in
zlib, https://github.com/madler/zlib. The Huffman table construction and decoding follow puff
closely; the decoder was made resumable and gained gzip framing and CRC-32. puff's notice is kept
at the top of `tg_inflate.c`:

```
Copyright (C) 2002-2013 Mark Adler, all rights reserved
version 2.3, 21 Jan 2013

This software is provided 'as-is', without any express or implied
warranty.  In no event will the author be held liable for any damages
arising from the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

1. The origin of this software must not be misrepresented; you must not
   claim that you wrote the original software. If you use this software
   in a product, an acknowledgment in the product documentation would be
   appreciated but is not required.
2. Altered source versions must be plainly marked as such, and must not be
   misrepresented as being the original software.
3. This notice may not be removed or altered from any source distribution.

Mark Adler    madler@alumni.caltech.edu
```
