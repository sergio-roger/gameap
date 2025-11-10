package cache_test

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/gameap/gameap/internal/cache"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	_ "github.com/jackc/pgx/v5/stdlib" // PostgreSQL driver
)

func TestPostgreSQLCache(t *testing.T) {
	testPostgresDSN := os.Getenv("TEST_POSTGRES_DSN")
	if testPostgresDSN == "" {
		t.Skip("Skipping PostgreSQL cache tests because TEST_POSTGRES_DSN is not set")
	}

	db, err := sql.Open("pgx", testPostgresDSN)
	require.NoError(t, err)
	defer db.Close()

	_, _ = db.Exec("DROP TABLE IF EXISTS kv_store")

	suite.Run(t, cache.NewCacheSuite(
		func(_ *testing.T) cache.Cache {
			return cache.NewPostgreSQL(db)
		},
	))

	_, _ = db.Exec("DROP TABLE IF EXISTS kv_store")
}

func TestPostgreSQLCacheCleanupExpired(t *testing.T) {
	testPostgresDSN := os.Getenv("TEST_POSTGRES_DSN")
	if testPostgresDSN == "" {
		t.Skip("Skipping PostgreSQL cache tests because TEST_POSTGRES_DSN is not set")
	}

	db, err := sql.Open("pgx", testPostgresDSN)
	require.NoError(t, err)
	defer db.Close()

	_, _ = db.Exec("DROP TABLE IF EXISTS kv_store")

	c := cache.NewPostgreSQL(db)
	ctx := context.Background()

	_ = c.Clear(ctx)

	// This test is PostgreSQL-specific as CleanupExpired is not part of the Cache interface
	t.Run("cleanup_expired", func(t *testing.T) {
		err := c.Set(ctx, "expired_1", "value1", cache.WithExpiration(1*time.Millisecond))
		require.NoError(t, err)

		err = c.Set(ctx, "expired_2", "value2", cache.WithExpiration(1*time.Millisecond))
		require.NoError(t, err)

		err = c.Set(ctx, "not_expired", "value3", cache.WithExpiration(10*time.Second))
		require.NoError(t, err)

		err = c.Set(ctx, "no_expiration", "value4")
		require.NoError(t, err)

		time.Sleep(10 * time.Millisecond)

		err = c.CleanupExpired(ctx)
		require.NoError(t, err)

		_, err = c.Get(ctx, "expired_1")
		require.ErrorIs(t, err, cache.ErrNotFound)

		_, err = c.Get(ctx, "expired_2")
		require.ErrorIs(t, err, cache.ErrNotFound)

		value, err := c.Get(ctx, "not_expired")
		require.NoError(t, err)
		require.Equal(t, "value3", value)

		value, err = c.Get(ctx, "no_expiration")
		require.NoError(t, err)
		require.Equal(t, "value4", value)
	})

	_, _ = db.Exec("DROP TABLE IF EXISTS kv_store")
}

func BenchmarkPostgreSQLCache_Set(b *testing.B) {
	testPostgresDSN := os.Getenv("TEST_POSTGRES_DSN")
	if testPostgresDSN == "" {
		b.Skip("Skipping PostgreSQL cache benchmarks because TEST_POSTGRES_DSN is not set")
	}

	db, err := sql.Open("pgx", testPostgresDSN)
	require.NoError(b, err)
	defer db.Close()

	_, _ = db.Exec("DROP TABLE IF EXISTS kv_store")

	c := cache.NewPostgreSQL(db)
	ctx := context.Background()

	b.ResetTimer()
	for range b.N {
		key := "bench_key_" + string(rune(b.N%1000))
		_ = c.Set(ctx, key, "benchmark_value")
	}
}

func BenchmarkPostgreSQLCache_Get(b *testing.B) {
	testPostgresDSN := os.Getenv("TEST_POSTGRES_DSN")
	if testPostgresDSN == "" {
		b.Skip("Skipping PostgreSQL cache benchmarks because TEST_POSTGRES_DSN is not set")
	}

	db, err := sql.Open("pgx", testPostgresDSN)
	require.NoError(b, err)
	defer db.Close()

	_, _ = db.Exec("DROP TABLE IF EXISTS kv_store")

	c := cache.NewPostgreSQL(db)
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

func BenchmarkPostgreSQLCache_Delete(b *testing.B) {
	testPostgresDSN := os.Getenv("TEST_POSTGRES_DSN")
	if testPostgresDSN == "" {
		b.Skip("Skipping PostgreSQL cache benchmarks because TEST_POSTGRES_DSN is not set")
	}

	db, err := sql.Open("pgx", testPostgresDSN)
	require.NoError(b, err)
	defer db.Close()

	_, _ = db.Exec("DROP TABLE IF EXISTS kv_store")

	c := cache.NewPostgreSQL(db)
	ctx := context.Background()

	b.ResetTimer()
	for i := range b.N {
		key := "bench_key_" + string(rune(i))
		_ = c.Set(ctx, key, "benchmark_value")
		_ = c.Delete(ctx, key)
	}
}
