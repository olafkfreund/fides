package api

import "golang.org/x/sys/unix"

func limitSchemaWorkerResources() error {
	for resource, maxValue := range map[int]uint64{unix.RLIMIT_DATA: schemaWorkerDataLimit, unix.RLIMIT_CPU: 2} {
		var limit unix.Rlimit
		if err := unix.Getrlimit(resource, &limit); err != nil {
			return err
		}
		limit.Cur = min(limit.Cur, maxValue)
		limit.Max = min(limit.Max, maxValue)
		if err := unix.Setrlimit(resource, &limit); err != nil {
			return err
		}
	}
	return nil
}
