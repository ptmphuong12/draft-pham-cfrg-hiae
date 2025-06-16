## HiAE: A High-Throughput Authenticated Encryption Algorithm for Cross-Platform Efficiency

This is the working area for the IETF Draft: "The Fast Software Authenticated Encryption HiAE"

DataTracker Page: https://datatracker.ietf.org/doc/draft-pham-cfrg-hiae/

White Paper "[HiAE: A High-Throughput Authenticated Encryption Algorithm for Cross-Platform Efficiency](https://eprint.iacr.org/2025/377)"

## Known Implementatio

Official Implementation: https://github.com/Concyclics/HiAE/tree/main
Zig language: https://github.com/jedisct1/zig-hiae

## Design Rational

The HiAE is an AES-based AEAD cipher that mainly focuses on cross-platform efficiency(ARM and x86) and achieves the fastest speed on the latest ARM and x86 architectures.

#### XAXX Structure

![XAXX.drawio](XAXX.drawio.png)

## Speed Benchmark

View the full speed benchmark [here](https://concyclics.github.io/HiAE/Speed/speed.html)

![speed](Throughput.png)

#### Bench HiAE on your machine

```bash
gcc -O3 -march=native -I code code/*.c test/performance_test.c -o perf_test
./perf_test
```

## Applications

#### HiAE-HMAC

The File verification with HiAE MAC mode.

**compile**

```bash
gcc -O3 -march=native -I code code/*.c app/HiAE-MAC.c -o HiAE-MAC
```

**Usage**

```bash
./HiAE-MAC <input_file> <key> <iv> [buffer_size (MB)]
```

**Example**

```bash
$ ./HiAE-MAC README.md 1926 0817
KEY = 1926000000000000000000000000000000000000000000000000000000000000
IV = 08170000000000000000000000000000
MAC: c9e1326675a5e70c3609c8eacfe89b83
MAC file README.md (2079 bytes) in 0.000100 seconds
Speed: 0.019362 GB/s
```

#### File AEAD Encryption & Decryption

The File encryption will auto append the AEAD tag after the file for integrity protection.

**compile**

```bash
gcc -O3 -march=native -I code code/*.c app/HiAE-File-AEAD.c -o HiAE-File-AEAD
```

**Usage**

```bash
./HiAE-File-AEAD <encrypt/decrypt> <input_file> <output_file> <key> <iv> [buffer_size (MB)]
```

**Example**

```bash
$ ./HiAE-File-AEAD encrypt README.md README.enc 1926 0817
KEY = 1926000000000000000000000000000000000000000000000000000000000000
IV = 08170000000000000000000000000000
Encrypted README.md to README.enc (2079 bytes) in 0.000178 seconds
Speed: 0.010878 GB/s

$ ./HiAE-File-AEAD decrypt README.enc README.md 1926 0817
KEY = 1926000000000000000000000000000000000000000000000000000000000000
IV = 08170000000000000000000000000000
Authorization Passed.
Decrypted README.enc to README.md (2079 bytes) in 0.000220 seconds
Speed: 0.008801 GB/s 
```


## Contributing

Contributions can be made by creating pull requests or contact the authors.


