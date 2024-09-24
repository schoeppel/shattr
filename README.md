# shattr
Save SHA-256 digest of file contents in extended attribute

```
Usage: ./shattr [OPTION]... [FILE]...
Save SHA-256 digest of file contents in extended attribute.
Options:
  -s      save digest in extended attribute
  -S      save digest in extended attribute (force recalc)
  -c      read digest from extended attribute and check file
  -p      print SHA-256 digest
  -P      print SHA-256 digest (don't use extended attribute)
  -t      convert (c)shatag attributes
  -b      run internal benchmark
Default option is '-s'
```

Only a single attribute is used for both digest (base64 encoded) and modification timestamp (64-bit nanoseconds). The format is designed to be compact. This can allow storing the extended attribute in-inode.

Example:

    user.shattr="sSu/jREnolcCSLt8zoyibRT0imkyX1jHfk5cFj/+Qus=17f741633264996a"

# Speed

AMD Ryzen 7 PRO 6850U
```
shattr -b
1073741824 bytes in 473770724 nsecs: 2266 MByte/s
```

Intel Core i5-6400
```
shattr -b
1073741824 bytes in 6979976961 nsecs: 153 MByte/s
```

https://en.wikipedia.org/wiki/Intel_SHA_extensions are used if available.
