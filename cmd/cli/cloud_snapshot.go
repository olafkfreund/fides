package main

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"slices"
	"strings"
	"time"
)

type snapshotCommand func(context.Context, string, ...string) ([]byte, error)

func runSnapshotCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	switch name {
	case "gcloud", "az", "aws":
	default:
		return nil, errors.New("unsupported provider CLI")
	}
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 G702 -- allowlisted CLI, with argv and no shell
	cmd.WaitDelay = time.Second
	out, err := cmd.Output()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if errors.Is(err, exec.ErrNotFound) {
		return nil, errors.New("provider CLI not found")
	}
	if err != nil {
		return nil, errors.New("provider CLI command failed")
	}
	return out, nil
}

func cloudRunSnapshotArtifacts(ctx context.Context, service, region, project string, run snapshotCommand) ([]map[string]string, error) {
	if service == "" || strings.HasPrefix(service, "-") || region == "" {
		return nil, errors.New("a valid --service and --region are required")
	}
	flags := []string{"--quiet", "--region=" + region, "--format=json"}
	if project != "" {
		flags = append(flags, "--project="+project)
	}
	readTraffic := func() ([]string, error) {
		out, err := run(ctx, "gcloud", append([]string{"run", "services", "describe", service}, flags...)...)
		if err != nil {
			return nil, errors.New("could not describe the Cloud Run service")
		}
		return cloudRunServingRevisions(out)
	}
	revisions, err := readTraffic()
	if err != nil {
		return nil, err
	}
	var artifacts []map[string]string
	for _, revision := range revisions {
		out, err := run(ctx, "gcloud", append([]string{"run", "revisions", "describe", revision}, flags...)...)
		if err != nil {
			return nil, errors.New("could not describe the Cloud Run revision")
		}
		got, err := cloudRunRevisionArtifacts(out, service, revision)
		if err != nil {
			return nil, err
		}
		artifacts = append(artifacts, got...)
	}
	current, err := readTraffic()
	if err != nil {
		return nil, err
	}
	if !slices.Equal(revisions, current) {
		return nil, errors.New("serving Cloud Run revisions changed during collection")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return artifacts, nil
}

func cloudRunServingRevisions(out []byte) ([]string, error) {
	var state struct {
		Status struct {
			Traffic []struct {
				RevisionName string `json:"revisionName"`
				Percent      int    `json:"percent"`
				Tag          string `json:"tag"`
			} `json:"traffic"`
		} `json:"status"`
	}
	if json.Unmarshal(out, &state) != nil {
		return nil, errors.New("invalid Cloud Run service response")
	}

	revisions := make(map[string]bool)
	total := 0
	for _, target := range state.Status.Traffic {
		if target.Percent < 0 || target.Percent > 100 {
			return nil, errors.New("invalid Cloud Run traffic allocation")
		}
		total += target.Percent
		// Tagged revisions serve at their own URL even with zero default traffic.
		if target.Percent == 0 && target.Tag == "" {
			continue
		}
		if target.RevisionName == "" || strings.HasPrefix(target.RevisionName, "-") {
			return nil, errors.New("unresolved Cloud Run traffic target")
		}
		revisions[target.RevisionName] = true
	}
	if total != 100 {
		return nil, errors.New("incomplete Cloud Run traffic allocation")
	}

	names := make([]string, 0, len(revisions))
	for revision := range revisions {
		names = append(names, revision)
	}
	slices.Sort(names)
	return names, nil
}

func cloudRunRevisionArtifacts(out []byte, service, revision string) ([]map[string]string, error) {
	type containerStatus struct {
		Name        string `json:"name"`
		ImageDigest string `json:"imageDigest"`
	}
	var state struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Spec struct {
			Containers []struct {
				Name string `json:"name"`
			} `json:"containers"`
		} `json:"spec"`
		Status struct {
			ImageDigest       string            `json:"imageDigest"`
			ContainerStatuses []containerStatus `json:"containerStatuses"`
		} `json:"status"`
	}

	if json.Unmarshal(out, &state) != nil || state.Metadata.Name != revision || len(state.Spec.Containers) == 0 {
		return nil, errors.New("invalid Cloud Run revision response")
	}
	statuses := state.Status.ContainerStatuses
	if len(statuses) == 0 && len(state.Spec.Containers) == 1 {
		statuses = []containerStatus{{Name: state.Spec.Containers[0].Name, ImageDigest: state.Status.ImageDigest}}
	}
	digests := make(map[string]string, len(statuses))
	for _, status := range statuses {
		digest := status.ImageDigest
		if _, suffix, ok := strings.Cut(digest, "@"); ok {
			digest = suffix
		}
		hexDigest, ok := strings.CutPrefix(digest, "sha256:")
		if !ok || !isSHA256Hex(hexDigest) || digests[status.Name] != "" {
			return nil, errors.New("unverified Cloud Run container digest")
		}
		digests[status.Name] = strings.ToLower(hexDigest)
	}
	if len(digests) != len(state.Spec.Containers) {
		return nil, errors.New("incomplete Cloud Run container status")
	}

	var artifacts []map[string]string
	for _, container := range state.Spec.Containers {
		digest := digests[container.Name]
		if digest == "" {
			return nil, errors.New("incomplete Cloud Run container status")
		}
		delete(digests, container.Name)
		name := service + "/" + revision
		if container.Name != "" {
			name += "/" + container.Name
		}
		artifacts = append(artifacts, map[string]string{"sha256": digest, "service_name": name})
	}
	return artifacts, nil
}
