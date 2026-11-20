package engine

import (
	"fmt"
	"testing"
)

// BenchmarkLocalAdvisoryMatching is a reproducible CPU-only microbenchmark.
// All components and advisory IDs are synthetic; there are no network calls.
func BenchmarkLocalAdvisoryMatching(b *testing.B) {
	plugins := make(map[string]string, 50)
	db := make(VulnDB, 50)
	for i := 0; i < 50; i++ {
		slug := fmt.Sprintf("fixture-component-%03d", i)
		plugins[slug] = "2.4.1"
		advisories := make([]VulnEntry, 8)
		for j := range advisories {
			advisories[j] = VulnEntry{
				ID:            fmt.Sprintf("FIXTURE-%03d-%d", i, j),
				CVSS:          5.0,
				From:          "2.0",
				FromInclusive: true,
				To:            "2.9",
				ToInclusive:   true,
			}
		}
		db[slug] = advisories
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Analyze(plugins, db, true)
	}
}
