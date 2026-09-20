# 256 reference

reference compressor for the [256 challenge](https://github.com/birlug/256).

## results

```
  compressed   1,932,409 bytes
  code         31,800 bytes
  SCORE        1,964,209 bytes
  time         14.7s
```

## phases

1. split the file into chunks after the `UNCLEJACKIE` header
2. transform payloads (see hint 3 in the [256 challenge readme](https://github.com/birlug/256/blob/master/docs/README.md))
3. reconstruct what we can from structure: math sequences, images, waves, prngs, and the rest
4. compress anything left with lzma

the source could be minified for a better score, but this repo keeps it readable and maintainable instead.
