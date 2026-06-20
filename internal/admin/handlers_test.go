package admin

import (
	"testing"
	"time"

	"github.com/wicket-vpn/wicket/internal/db"
)

func TestBucketMetricDeltas(t *testing.T) {
	t0 := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)
	snap := func(minutesAfter int, sent, recv int64) *db.MetricSnapshot {
		return &db.MetricSnapshot{
			BytesSent:     sent,
			BytesReceived: recv,
			RecordedAt:    t0.Add(time.Duration(minutesAfter) * time.Minute),
		}
	}

	t.Run("fewer than two snapshots yields no points", func(t *testing.T) {
		if got := bucketMetricDeltas(nil); len(got) != 0 {
			t.Fatalf("expected 0 points, got %d", len(got))
		}
		if got := bucketMetricDeltas([]*db.MetricSnapshot{snap(0, 100, 100)}); len(got) != 0 {
			t.Fatalf("expected 0 points, got %d", len(got))
		}
	})

	t.Run("sums deltas within an hour bucket", func(t *testing.T) {
		points := bucketMetricDeltas([]*db.MetricSnapshot{
			snap(0, 1000, 500),
			snap(1, 1500, 600), // +500 sent, +100 recv
			snap(2, 2000, 700), // +500 sent, +100 recv
		})
		if len(points) != 1 {
			t.Fatalf("expected 1 bucket, got %d: %+v", len(points), points)
		}
		if points[0].BytesSent != 1000 || points[0].BytesReceived != 200 {
			t.Fatalf("expected sent=1000 recv=200, got sent=%v recv=%v", points[0].BytesSent, points[0].BytesReceived)
		}
	})

	t.Run("a gap over 5 minutes still counts (regression: used to be dropped)", func(t *testing.T) {
		// Device connects briefly, disconnects, reconnects an hour later — no
		// two samples within 5 minutes, but the traffic is real and must show.
		points := bucketMetricDeltas([]*db.MetricSnapshot{
			snap(0, 1000, 1000),
			snap(90, 2000, 1500), // 90 min later, +1000 sent +500 recv
		})
		var total float64
		for _, p := range points {
			total += p.BytesSent + p.BytesReceived
		}
		if total != 1500 {
			t.Fatalf("expected total traffic of 1500 across buckets, got %v (%+v)", total, points)
		}
	})

	t.Run("counter reset (peer re-added) clamps to zero, not negative", func(t *testing.T) {
		points := bucketMetricDeltas([]*db.MetricSnapshot{
			snap(0, 5000, 5000),
			snap(1, 100, 200), // counters reset after peer re-add
		})
		if len(points) != 1 {
			t.Fatalf("expected 1 bucket, got %d", len(points))
		}
		if points[0].BytesSent < 0 || points[0].BytesReceived < 0 {
			t.Fatalf("expected non-negative deltas, got sent=%v recv=%v", points[0].BytesSent, points[0].BytesReceived)
		}
	})

	t.Run("out-of-order timestamps are skipped", func(t *testing.T) {
		points := bucketMetricDeltas([]*db.MetricSnapshot{
			snap(5, 1000, 1000),
			snap(0, 2000, 2000), // earlier timestamp, later in slice
		})
		if len(points) != 0 {
			t.Fatalf("expected 0 points for non-increasing timestamps, got %d: %+v", len(points), points)
		}
	})
}
