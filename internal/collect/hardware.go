package collect

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/sensors"

	"github.com/soc-foundry/varro/internal/model"
)

const (
	maxTempSensors = 20
	maxIODevices   = 10
)

type diskIOPrev struct {
	readBytes, writeBytes uint64
	readCount, writeCount uint64
}

// sampleHardware fills temperature readings and per-device disk I/O rates.
func (c *Collector) sampleHardware(ctx context.Context, now time.Time, snap *model.Snapshot) {
	c.sampleTemps(ctx, snap)
	c.sampleDiskIO(ctx, now, snap)
}

func (c *Collector) sampleTemps(ctx context.Context, snap *model.Snapshot) {
	temps, err := sensors.TemperaturesWithContext(ctx)
	if err != nil && len(temps) == 0 {
		return
	}
	for _, t := range temps {
		if t.Temperature <= 0 {
			continue
		}
		snap.Hardware.Temps = append(snap.Hardware.Temps, model.TempReading{
			Sensor:  t.SensorKey,
			Celsius: t.Temperature,
			High:    t.High,
		})
	}
	sort.Slice(snap.Hardware.Temps, func(i, j int) bool {
		return snap.Hardware.Temps[i].Celsius > snap.Hardware.Temps[j].Celsius
	})
	if len(snap.Hardware.Temps) > maxTempSensors {
		snap.Hardware.Temps = snap.Hardware.Temps[:maxTempSensors]
	}
}

// skipIODevice filters out pseudo-devices that only add noise.
func skipIODevice(name string) bool {
	for _, p := range []string{"loop", "ram", "zram", "sr"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func (c *Collector) sampleDiskIO(ctx context.Context, now time.Time, snap *model.Snapshot) {
	counters, err := disk.IOCountersWithContext(ctx)
	if err != nil {
		return
	}
	dt := now.Sub(c.prevIOTime).Seconds()
	current := map[string]diskIOPrev{}
	for name, io := range counters {
		if skipIODevice(name) {
			continue
		}
		cur := diskIOPrev{io.ReadBytes, io.WriteBytes, io.ReadCount, io.WriteCount}
		current[name] = cur
		prev, ok := c.prevDiskIO[name]
		if !ok || dt <= 0 || c.prevIOTime.IsZero() ||
			cur.readBytes < prev.readBytes || cur.writeBytes < prev.writeBytes {
			continue
		}
		snap.Hardware.DiskIO = append(snap.Hardware.DiskIO, model.DiskIORate{
			Device:    name,
			ReadBps:   float64(cur.readBytes-prev.readBytes) / dt,
			WriteBps:  float64(cur.writeBytes-prev.writeBytes) / dt,
			ReadIOPS:  float64(cur.readCount-prev.readCount) / dt,
			WriteIOPS: float64(cur.writeCount-prev.writeCount) / dt,
		})
	}
	c.prevDiskIO = current
	c.prevIOTime = now

	// Busiest devices first; cap the list.
	sort.Slice(snap.Hardware.DiskIO, func(i, j int) bool {
		a, b := snap.Hardware.DiskIO[i], snap.Hardware.DiskIO[j]
		return a.ReadBps+a.WriteBps > b.ReadBps+b.WriteBps
	})
	if len(snap.Hardware.DiskIO) > maxIODevices {
		snap.Hardware.DiskIO = snap.Hardware.DiskIO[:maxIODevices]
	}
}

// MaxTemp returns the hottest sensor reading, 0 if none.
func MaxTemp(h model.HardwareMetrics) float64 {
	var m float64
	for _, t := range h.Temps {
		if t.Celsius > m {
			m = t.Celsius
		}
	}
	return m
}

// TotalIORates sums read/write byte rates across devices.
func TotalIORates(h model.HardwareMetrics) (read, write float64) {
	for _, d := range h.DiskIO {
		read += d.ReadBps
		write += d.WriteBps
	}
	return read, write
}
