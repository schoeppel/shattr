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

# Example
user.shattr="sSu/jREnolcCSLt8zoyibRT0imkyX1jHfk5cFj/+Qus=17f741633264996a"
