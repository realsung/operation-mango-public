#!/bin/sh

rm -rf 'a.out=result'
mango ./a.out.strip --results ./a.out=result --disable-progress
```

test.c
