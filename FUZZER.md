The `fuzzer` directory contains several fuzz targets that make use of asan and
[libFuzzer](https://llvm.org/docs/LibFuzzer.html) from clang 10 or later to test
functions that are expected to process untrusted inputs.

To build:

```
CXX=clang++-10 meson build
ninja -C build fuzzer-$name
```

where `$name` can be any of the files in the `fuzzer` directory.

You can then run the fuzzer as `build/fuzzer-$name`.  The basic mode will run
indefinitely until a problem is found.  Pass `-help=1` to see additional fuzzer
options.
