# Cache


## Benchmark

### In-Memory

```
cpu: Apple M3 Max

BenchmarkInMemoryCache_Set
BenchmarkInMemoryCache_Set-14    	19873910	        57.13 ns/op

BenchmarkInMemoryCache_Delete
BenchmarkInMemoryCache_Delete-14    	12777964	        83.30 ns/op
```

### Redis

```
cpu: Apple M3 Max

BenchmarkRedisCache_Get
BenchmarkRedisCache_Get-14    	    7922	    133190 ns/op

BenchmarkRedisCache_Delete
BenchmarkRedisCache_Delete-14    	    4239	    289880 ns/op
```

### MySQL

```
cpu: Apple M3 Max

BenchmarkMySQLCache_Get
BenchmarkMySQLCache_Get-14    	    4654	    297790 ns/op

BenchmarkMySQLCache_Delete
BenchmarkMySQLCache_Delete-14    	    1573	    820273 ns/op

```

### PostgreSQL

```
cpu: Apple M3 Max

BenchmarkPostgreSQLCache_Get
BenchmarkPostgreSQLCache_Get-14    	    7800	    147640 ns/op

BenchmarkPostgreSQLCache_Delete
BenchmarkPostgreSQLCache_Delete-14    	    3058	    331498 ns/op
```