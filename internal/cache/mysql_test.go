package cache_test

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/gameap/gameap/internal/cache"
	_ "github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

func TestMySQLCache(t *testing.T) {
	testMySQLDSN := os.Getenv("TEST_MYSQL_DSN")
	if testMySQLDSN == "" {
		t.Skip("Skipping MySQL cache tests because TEST_MYSQL_DSN is not set")
	}

	db, err := sql.Open("mysql", testMySQLDSN)
	require.NoError(t, err)
	defer db.Close()

	_, _ = db.Exec("DROP TABLE IF EXISTS kv_store")

	suite.Run(t, cache.NewCacheSuite(
		func(_ *testing.T) cache.Cache {
			return cache.NewMySQL(db)
		},
	))

	_, _ = db.Exec("DROP TABLE IF EXISTS kv_store")
}

func BenchmarkMySQLCache_Set(b *testing.B) {
	testMySQLDSN := os.Getenv("TEST_MYSQL_DSN")
	if testMySQLDSN == "" {
		b.Skip("Skipping MySQL cache benchmarks because TEST_MYSQL_DSN is not set")
	}

	db, err := sql.Open("mysql", testMySQLDSN)
	require.NoError(b, err)
	defer db.Close()

	_, _ = db.Exec("DROP TABLE IF EXISTS kv_store")

	c := cache.NewMySQL(db)
	ctx := context.Background()

	b.ResetTimer()
	for range b.N {
		key := "bench_key_" + string(rune(b.N%1000))
		_ = c.Set(ctx, key, "benchmark_value")
	}
}

func BenchmarkMySQLCache_Get(b *testing.B) {
	testMySQLDSN := os.Getenv("TEST_MYSQL_DSN")
	if testMySQLDSN == "" {
		b.Skip("Skipping MySQL cache benchmarks because TEST_MYSQL_DSN is not set")
	}

	db, err := sql.Open("mysql", testMySQLDSN)
	require.NoError(b, err)
	defer db.Close()

	_, _ = db.Exec("DROP TABLE IF EXISTS kv_store")

	c := cache.NewMySQL(db)
	ctx := context.Background()

	for i := range 1000 {
		key := "bench_key_" + string(rune(i))
		_ = c.Set(ctx, key, "benchmark_value")
	}

	b.ResetTimer()
	for range b.N {
		key := "bench_key_" + string(rune(b.N%1000))
		_, _ = c.Get(ctx, key)
	}
}

func BenchmarkMySQLCache_Delete(b *testing.B) {
	testMySQLDSN := os.Getenv("TEST_MYSQL_DSN")
	if testMySQLDSN == "" {
		b.Skip("Skipping MySQL cache benchmarks because TEST_MYSQL_DSN is not set")
	}

	db, err := sql.Open("mysql", testMySQLDSN)
	require.NoError(b, err)
	defer db.Close()

	_, _ = db.Exec("DROP TABLE IF EXISTS kv_store")

	c := cache.NewMySQL(db)
	ctx := context.Background()

	b.ResetTimer()
	for i := range b.N {
		key := "bench_key_" + string(rune(i))
		_ = c.Set(ctx, key, "benchmark_value")
		_ = c.Delete(ctx, key)
	}
}
