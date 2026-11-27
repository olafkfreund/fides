package main

import (
	"encoding/json"
	"flag"
	"fmt"
	neturl "net/url"
	"os"
	"os/exec"
	"strings"

	"fides/pkg/cliprogress"
	"fides/pkg/exitcode"
)

// handleEnvCreate: fides env create --name <n> [--type k8s] [--description <d>]
// Creates (or upserts by name) an environment to report snapshots into.
func handleEnvCreate(config CLIConfig, args []string) {
	cmd := flag.NewFlagSet("env create", flag.ExitOnError)
	name := cmd.String("name", "", "environment name")
	typ := cmd.String("type", "k8s", "runtime type: docker|k8s|ecs|lambda|server")
	desc := cmd.String("description", "", "description")
	cmd.Parse(args)
	if *name == "" {
		fmt.Println("Usage: fides env create --name <name> [--type k8s] [--description <d>]")
		os.Exit(1)
	}
	body, err := postRequest(config, "/api/v1/environments", map[string]any{"name": *name, "type": *typ, "description": *desc})
	fail(err, "create environment")
	fmt.Println(body)
}

// handleEnvList: fides env list — the org's environments.
func handleEnvList(config CLIConfig, _ []string) {
	body, err := getList(config, "/api/v1/environments")
	fail(err, "list environments")
	fmt.Println(body)
}

// stringSlice collects a repeatable flag (e.g. --rule ... --rule ...).
type stringSlice []string

func (s *stringSlice) String() string     { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error { *s = append(*s, v); return nil }

// fides env verify --env <id> --server <name> --tool <t> --rule '...' [--rules-file <f>]
func handleEnvVerify(config CLIConfig, args []string) {
	cmd := flag.NewFlagSet("env verify", flag.ExitOnError)
	env := cmd.String("env", "", "environment UUID")
	server := cmd.String("server", "", "MCP server/connection name")
	tool := cmd.String("tool", "get_pods", "MCP tool name")
	rulesFile := cmd.String("rules-file", "", "file with one jq rule per line")
	var rules stringSlice
	cmd.Var(&rules, "rule", "a jq compliance rule (repeatable)")
	cmd.Parse(args)
	if *env == "" || *server == "" || *tool == "" {
		fmt.Println("Usage: fides env verify --env <id> --server <name> --tool <t> --rule '.pods[].status == \"Ready\"' [--rules-file <f>]")
		os.Exit(1)
	}
	rl := []string(rules)
	if *rulesFile != "" {
		data, err := os.ReadFile(*rulesFile) // #nosec G304 G703 -- CLI reads a user-specified rules file by design
		fail(err, "read rules file")
		for _, line := range strings.Split(string(data), "\n") {
			if s := strings.TrimSpace(line); s != "" {
				rl = append(rl, s)
			}
		}
	}
	if len(rl) == 0 {
		fmt.Println("Error: provide at least one --rule or a --rules-file")
		os.Exit(1)
	}
	p := cliprogress.New(os.Stderr, false)
	p.StartStage("Running runtime compliance check")
	body, err := postRequest(config, "/api/v1/environments/mcp/verify", map[string]any{
		"environment_id": *env, "server_name": *server, "tool_name": *tool,
		"arguments": map[string]any{}, "rules": rl,
	})
	if err != nil {
		p.CompleteStage("")
		fail(err, "verify environment compliance")
	}
	p.CompleteStage("Runtime checked")
	fmt.Println(body)
	if strings.Contains(body, "\"compliant\":false") {
		os.Exit(exitcode.Violation) // so CI can gate on runtime compliance
	}
}

// fides env diff --env <id> [--from <snap> --to <snap>] [--reevaluate-change CHGxxxx]
func handleEnvDiff(config CLIConfig, args []string) {
	cmd := flag.NewFlagSet("env diff", flag.ExitOnError)
	env := cmd.String("env", "", "environment UUID")
	from := cmd.String("from", "", "from snapshot UUID (default: 2nd most recent)")
	to := cmd.String("to", "", "to snapshot UUID (default: most recent)")
	reevaluateChange := cmd.String("reevaluate-change", "", "ServiceNow change number (e.g. CHG0030192); on detected drift, escalates its risk and posts a work note")
	cmd.Parse(args)
	if *env == "" {
		fmt.Println("Usage: fides env diff --env <id> [--from <snap> --to <snap>] [--reevaluate-change CHGxxxx]")
		os.Exit(1)
	}

	if *reevaluateChange != "" {
		body, err := postRequest(config, "/api/v1/environments/"+*env+"/snapshots/reevaluate-change", map[string]any{
			"change_number": *reevaluateChange, "from": *from, "to": *to,
		})
		fail(err, "drift re-evaluation")
		fmt.Println(body)
		if strings.Contains(body, "\"drift_detected\":true") {
			os.Exit(exitcode.Violation) // so CI/pipelines can react to post-approval drift
		}
		return
	}

	q := neturl.Values{}
	setIf(q, "from", *from)
	setIf(q, "to", *to)
	body, err := getRequest(config, "/api/v1/environments/"+*env+"/snapshots/diff?"+q.Encode())
	fail(err, "snapshot diff")
	fmt.Println(body)
}

// fides env archive --env <id>   |   fides env unarchive --env <id>
//
// Retires an environment from the compliance picture without deleting it. It
// leaves the control-coverage denominator and the default listing; its
// snapshots, policies and allow-lists stay exactly where they are, and the id
// keeps resolving, so anything still pointing at it goes on working.
//
// The e2e suite creates one environment per run and deletes none, so without
// this every abandoned run permanently lowers every control's coverage.
func handleEnvArchive(config CLIConfig, args []string, archive bool) {
	verb := "archive"
	if !archive {
		verb = "unarchive"
	}
	cmd := flag.NewFlagSet("env "+verb, flag.ExitOnError)
	env := cmd.String("env", "", "environment UUID")
	cmd.Parse(args)
	if *env == "" {
		fmt.Printf("Usage: fides env %s --env <id>\n", verb)
		os.Exit(1)
	}
	post(config, "/api/v1/environments/"+*env+"/"+verb, map[string]any{},
		"Environment "+verb+"d")
}

// fides logical-env create|list|add-member|state
func handleLogicalEnv(config CLIConfig, args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: fides logical-env <create|list|add-member|state> [--name --id --env]")
		os.Exit(1)
	}
	cmd := flag.NewFlagSet("logical-env "+args[0], flag.ExitOnError)
	name := cmd.String("name", "", "logical environment name")
	desc := cmd.String("description", "", "description")
	id := cmd.String("id", "", "logical environment UUID")
	env := cmd.String("env", "", "physical environment UUID")
	cmd.Parse(args[1:])
	switch args[0] {
	case "create":
		if *name == "" {
			fmt.Println("Error: --name is required")
			os.Exit(1)
		}
		post(config, "/api/v1/logical-environments", map[string]any{"name": *name, "description": *desc}, "")
	case "list":
		body, err := getList(config, "/api/v1/logical-environments")
		fail(err, "list logical environments")
		fmt.Println(body)
	case "add-member":
		if *id == "" || *env == "" {
			fmt.Println("Error: --id and --env are required")
			os.Exit(1)
		}
		post(config, "/api/v1/logical-environments/"+*id+"/members", map[string]any{"environment_id": *env}, "Member added")
	case "state":
		if *id == "" {
			fmt.Println("Error: --id is required")
			os.Exit(1)
		}
		body, err := getRequest(config, "/api/v1/logical-environments/"+*id+"/state")
		fail(err, "logical env state")
		fmt.Println(body)
	default:
		fmt.Println("Usage: fides logical-env <create|list|add-member|state>")
		os.Exit(1)
	}
}

func handleSnapshot(config CLIConfig, args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: fides snapshot docker --env <environment_id> [--container <name>]")
		os.Exit(1)
	}

	runtimeType := args[0]
	cmd := flag.NewFlagSet("snapshot", flag.ExitOnError)
	envID := cmd.String("env", "", "Environment UUID")
	containerName := cmd.String("container", "", "Target single container name (optional)")
	namespace := cmd.String("namespace", "", "Target namespace to filter pods (optional)")
	cluster := cmd.String("cluster", "", "ECS cluster name (required for 'ecs')")

	cmd.Parse(args[1:])

	if *envID == "" {
		fmt.Println("Error: --env is required")
		os.Exit(1)
	}

	var reportedArtifacts []map[string]string

	// TTY-only progress; silent when stderr is piped/redirected (e.g. CI).
	p := cliprogress.New(os.Stderr, false)
	p.StartStage("Snapshotting " + runtimeType + " runtime")

	if runtimeType == "docker" {
		// Query the local Docker daemon for running containers and resolve each
		// container's image content digest via `docker inspect`.
		fmt.Println("Ingesting running docker containers...")
		psArgs := []string{"ps", "--no-trunc", "--format", "{{.ID}}\t{{.Names}}"}
		if *containerName != "" {
			psArgs = append(psArgs, "--filter", "name="+*containerName)
		}
		out, err := exec.Command("docker", psArgs...).Output() // #nosec G204 -- fixed subcommand; container name filter passed as an arg
		if err != nil {
			fmt.Printf("Failed to query docker containers: %v\n", err)
			os.Exit(1)
		}
		reportedArtifacts = dockerSnapshotArtifacts(string(out), func(id string) (string, error) {
			d, derr := exec.Command("docker", "inspect", "--format", "{{.Image}}", id).Output() // #nosec G204 -- id from docker ps output
			return string(d), derr
		})
		if len(reportedArtifacts) == 0 {
			fmt.Println("No running docker containers found")
			os.Exit(0)
		}
	} else if runtimeType == "k8s" {
		// Least privilege: with --namespace, query only that namespace (needs a
		// namespaced Role) instead of the cluster-wide list (which needs a
		// ClusterRole). The k8s-reporter chart (charts/fides-k8s-reporter) sets
		// --namespace for its namespaced scope.
		fmt.Println("Ingesting running Kubernetes namespaces dynamically...")
		podsJSON, err := fetchPodsJSON(*namespace)
		if err != nil {
			// Fail, do not invent. This used to fall back to a hard-coded
			// "mock" digest and submit it as a runtime snapshot — a claim that
			// a specific image was running, indistinguishable downstream from
			// an observed one. Being unable to observe the cluster is not
			// evidence that something is running; it is the absence of
			// evidence, and a compliance tool has to say so. The docker branch
			// above already exits here (#406).
			fmt.Printf("Failed to query Kubernetes pods: %v\n", err)
			os.Exit(1)
		}
		var podList struct {
			Items []struct {
				Metadata struct {
					Name      string `json:"name"`
					Namespace string `json:"namespace"`
				} `json:"metadata"`
				Status struct {
					ContainerStatuses []struct {
						Name    string `json:"name"`
						Image   string `json:"image"`
						ImageID string `json:"imageID"`
					} `json:"containerStatuses"`
				} `json:"status"`
			} `json:"items"`
		}
		if err := json.Unmarshal(podsJSON, &podList); err == nil {
			for _, pod := range podList.Items {
				ns := pod.Metadata.Namespace
				// Filter out system namespaces
				if ns == "kube-system" || ns == "kube-public" || ns == "kube-node-lease" || ns == "ingress-nginx" || ns == "cert-manager" || ns == "external-secrets" || ns == "argocd" || ns == "gitlab" {
					continue
				}
				// Filter by namespace if requested
				if *namespace != "" && ns != *namespace {
					continue
				}
				for _, container := range pod.Status.ContainerStatuses {
					// Resolve the RUNNING digest, or report nothing for this
					// container.
					//
					// This used to fall back to container.ImageID, then to
					// container.Image -- a TAG -- and then truncate to 64 chars
					// so it fit the digest-shaped field. The result looked like
					// an observation and was not: a tag recorded as a sha256
					// can never equal a CI-registered artifact or an allowlist
					// entry, so it produced a shadow change that no correct
					// action could ever clear, and an environment stuck at
					// non-compliant for a reason its operator could not fix.
					//
					// Same rule as #406: when the runtime cannot tell us what
					// is running, say so. Do not invent a value that fits.
					digest := ""
					if _, after, found := strings.Cut(container.ImageID, "@sha256:"); found {
						digest = after
					}
					digest = strings.TrimPrefix(digest, "sha256:")
					if !isSHA256Hex(digest) {
						fmt.Fprintf(os.Stderr,
							"warning: skipping container %q in %s/%s: no sha256 digest in imageID %q (image %q)\n",
							container.Name, ns, pod.Metadata.Name, container.ImageID, container.Image)
						continue
					}

					reportedArtifacts = append(reportedArtifacts, map[string]string{
						"sha256":       digest,
						"service_name": container.Name,
					})
				}
			}
		} else {
			// Same reasoning as the query failure above: an unparseable pod
			// list left reportedArtifacts empty and the snapshot was still
			// submitted, asserting that nothing was running (#406).
			fmt.Printf("Failed to parse pod list json: %v\n", err)
			os.Exit(1)
		}
	}

	if runtimeType == "lambda" {
		fmt.Println("Ingesting AWS Lambda functions...")
		out, err := exec.Command("aws", "lambda", "list-functions", "--output", "json").Output() // #nosec G204 -- fixed 'aws' binary; args are constants
		if err != nil {
			fmt.Printf("Failed to query Lambda: %v\n", err)
			os.Exit(1)
		}
		reportedArtifacts = append(reportedArtifacts, lambdaSnapshotArtifacts(string(out), func(name string) (string, error) {
			b, gerr := exec.Command("aws", "lambda", "get-function", "--function-name", name, "--output", "json").Output() // #nosec G204 -- fixed 'aws' binary; name comes from AWS
			return string(b), gerr
		})...)
	}

	if runtimeType == "ecs" {
		if *cluster == "" {
			fmt.Println("Error: --cluster is required for 'ecs'")
			os.Exit(1)
		}
		fmt.Println("Ingesting AWS ECS tasks...")
		listOut, err := exec.Command("aws", "ecs", "list-tasks", "--cluster", *cluster, "--output", "json").Output() // #nosec G204 -- fixed 'aws' binary
		if err != nil {
			fmt.Printf("Failed to list ECS tasks: %v\n", err)
			os.Exit(1)
		}
		var tl struct {
			TaskArns []string `json:"taskArns"`
		}
		// Best-effort: unparseable output means no task ARNs, and the branch
		// below already treats that as "nothing running".
		//nolint:errcheck // documented above
		json.Unmarshal(listOut, &tl)
		if len(tl.TaskArns) > 0 {
			descArgs := append([]string{"ecs", "describe-tasks", "--cluster", *cluster, "--tasks"}, tl.TaskArns...)
			descArgs = append(descArgs, "--output", "json")
			descOut, err := exec.Command("aws", descArgs...).Output() // #nosec G204 -- fixed 'aws' binary; task arns come from AWS
			if err != nil {
				fmt.Printf("Failed to describe ECS tasks: %v\n", err)
				os.Exit(1)
			}
			reportedArtifacts = append(reportedArtifacts, ecsSnapshotArtifacts(string(descOut))...)
		}
	}

	p.CompleteStage(fmt.Sprintf("Collected %d artifact(s)", len(reportedArtifacts)))

	payload := map[string]interface{}{
		"environment_id": *envID,
		"artifacts":      reportedArtifacts,
	}

	p.StartStage("Reporting snapshot to Fides")
	respBody, err := postRequest(config, "/api/v1/snapshots", payload)
	if err != nil {
		p.CompleteStage("") // erase the spinner before the error
		fmt.Printf("Failed to report snapshot: %v\n", err)
		os.Exit(1)
	}
	p.CompleteStage("Snapshot submitted")

	fmt.Printf("Snapshot submitted successfully: %s\n", respBody)
}

// dockerSnapshotArtifacts parses `docker ps` output (tab-separated "ID<TAB>Names",
// one container per line) and resolves each container's image content digest via
// the inspect callback (`docker inspect --format {{.Image}}` -> "sha256:..."),
// producing snapshot artifacts. Containers whose digest can't be resolved are
// skipped rather than failing the whole snapshot.
func dockerSnapshotArtifacts(psOutput string, inspect func(id string) (string, error)) []map[string]string {
	var arts []map[string]string
	for _, line := range strings.Split(strings.TrimSpace(psOutput), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		id := strings.TrimSpace(parts[0])
		name := ""
		if len(parts) > 1 {
			name = strings.TrimSpace(parts[1])
		}
		img, err := inspect(id)
		if err != nil {
			continue
		}
		digest := strings.TrimPrefix(strings.TrimSpace(img), "sha256:")
		if digest == "" {
			continue
		}
		arts = append(arts, map[string]string{"sha256": digest, "service_name": name})
	}
	return arts
}

// fides allowlist add|list|check|remove
func handleAllowlist(config CLIConfig, args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: fides allowlist <add|list|check|remove> --env <id> [--sha <sha>|--image <ref>] [--reason <r>]\n" +
			"  add requires --reason (the entry records an accepted risk), and either\n" +
			"  --sha <hex> or --image <ref> to resolve the digest from the registry")
		os.Exit(1)
	}
	cmd := flag.NewFlagSet("allowlist "+args[0], flag.ExitOnError)
	env := cmd.String("env", "", "environment UUID")
	sha := cmd.String("sha", "", "artifact SHA256")
	image := cmd.String("image", "", "image reference to resolve the digest from, e.g. ghcr.io/org/app:1.2.3")
	reason := cmd.String("reason", "", "approval reason")
	cmd.Parse(args[1:])
	if *env == "" {
		fmt.Println("Error: --env is required")
		os.Exit(1)
	}
	base := "/api/v1/environments/" + *env + "/allowlist"
	switch args[0] {
	case "add":
		// --image resolves the digest from the registry so the operator does
		// not have to extract it from a pod's imageID by hand (#432). For a
		// multi-arch tag this resolves to the index digest, which is what a
		// runtime actually reports.
		if *sha == "" && *image != "" {
			resolved, err := resolveImageDigest(*image)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			*sha = resolved
			fmt.Printf("resolved %s -> sha256:%s\n", *image, resolved)
		}
		if *sha == "" {
			fmt.Println("Error: --sha or --image is required")
			os.Exit(1)
		}
		// Approving a digest records an accepted risk. Without a reason the
		// record cannot be evaluated later by anyone, including the person who
		// made it, so the server rejects it too -- fail here with the clearer
		// message rather than surfacing an HTTP 400.
		if strings.TrimSpace(*reason) == "" {
			fmt.Println("Error: --reason is required (an allowlist entry is an accepted risk and must say why)")
			os.Exit(1)
		}
		post(config, base, map[string]any{"artifact_sha256": *sha, "reason": *reason}, "Artifact approved for the environment")
	case "list":
		body, err := getList(config, base)
		fail(err, "list allowlist")
		fmt.Println(body)
	case "check":
		if *sha == "" {
			fmt.Println("Error: --sha is required")
			os.Exit(1)
		}
		body, err := getRequest(config, base+"?sha="+*sha)
		fail(err, "check allowlist")
		fmt.Println(body)
		if strings.Contains(body, "\"approved\":false") {
			os.Exit(exitcode.Violation) // so CI can gate a deploy on approval
		}
	case "remove":
		if *sha == "" {
			fmt.Println("Error: --sha is required")
			os.Exit(1)
		}
		body, err := deleteRequest(config, base+"/"+*sha)
		fail(err, "remove allowlist")
		fmt.Println(body)
	default:
		fmt.Println("Usage: fides allowlist <add|list|check|remove> --env <id> [--sha <sha>]")
		os.Exit(1)
	}
}

// fides remediation propose|list|get|approve|reject|apply
//
// Policy-driven auto-remediation with approval gates (issue #235): propose a
// low-risk fix (env tag, allowlist entry, or drift re-sync), have a distinct
// principal approve it, then apply. Apply always fails server-side unless the
// action is approved — this CLI never applies without going through approve.
func handleRemediation(config CLIConfig, args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: fides remediation <propose|list|get|approve|reject|apply> [flags]")
		os.Exit(1)
	}
	switch args[0] {
	case "propose":
		cmd := flag.NewFlagSet("remediation propose", flag.ExitOnError)
		env := cmd.String("env", "", "environment UUID")
		domain := cmd.String("domain", "", "env_tag | allowlist_entry | drift_resync")
		reason := cmd.String("reason", "", "why this remediation is being proposed")
		policy := cmd.String("policy", "", "policy UUID that was violated (optional)")
		tags := cmd.String("tags", "", "comma-separated key=value pairs (domain=env_tag)")
		sha := cmd.String("sha", "", "artifact SHA256 (domain=allowlist_entry|drift_resync)")
		cmd.Parse(args[1:])
		if *env == "" || *domain == "" {
			fmt.Println("Error: --env and --domain are required")
			os.Exit(1)
		}
		params := map[string]any{}
		switch *domain {
		case "env_tag":
			if *tags == "" {
				fmt.Println("Error: --tags is required for domain=env_tag (e.g. --tags team=payments,pci-scope=false)")
				os.Exit(1)
			}
			tagMap := map[string]string{}
			for _, kv := range strings.Split(*tags, ",") {
				parts := strings.SplitN(kv, "=", 2)
				if len(parts) != 2 || parts[0] == "" {
					fmt.Printf("Error: invalid --tags entry %q (want key=value)\n", kv)
					os.Exit(1)
				}
				tagMap[parts[0]] = parts[1]
			}
			params["tags"] = tagMap
		case "allowlist_entry", "drift_resync":
			if *sha == "" {
				fmt.Printf("Error: --sha is required for domain=%s\n", *domain)
				os.Exit(1)
			}
			params["artifact_sha256"] = *sha
		default:
			fmt.Println("Error: --domain must be one of env_tag, allowlist_entry, drift_resync")
			os.Exit(1)
		}
		body, err := postRequest(config, "/api/v1/remediation", map[string]any{
			"environment_id": *env, "domain": *domain, "reason": *reason, "policy_id": *policy, "params": params,
		})
		fail(err, "propose remediation")
		fmt.Println(body)
	case "list":
		cmd := flag.NewFlagSet("remediation list", flag.ExitOnError)
		status := cmd.String("status", "", "filter by status (proposed|approved|applied|rejected)")
		env := cmd.String("env", "", "filter by environment UUID")
		cmd.Parse(args[1:])
		q := neturl.Values{}
		setIf(q, "status", *status)
		setIf(q, "environment_id", *env)
		path := "/api/v1/remediation"
		if enc := q.Encode(); enc != "" {
			path += "?" + enc
		}
		body, err := getList(config, path)
		fail(err, "list remediation actions")
		fmt.Println(body)
	case "get":
		cmd := flag.NewFlagSet("remediation get", flag.ExitOnError)
		id := cmd.String("id", "", "remediation action UUID")
		cmd.Parse(args[1:])
		if *id == "" {
			fmt.Println("Error: --id is required")
			os.Exit(1)
		}
		body, err := getRequest(config, "/api/v1/remediation/"+*id)
		fail(err, "get remediation action")
		fmt.Println(body)
	case "approve":
		remediationTransition(config, args[1:], "approve")
	case "reject":
		remediationTransition(config, args[1:], "reject")
	case "apply":
		remediationTransition(config, args[1:], "apply")
	default:
		fmt.Println("Usage: fides remediation <propose|list|get|approve|reject|apply> [flags]")
		os.Exit(1)
	}
}

func remediationTransition(config CLIConfig, args []string, verb string) {
	cmd := flag.NewFlagSet("remediation "+verb, flag.ExitOnError)
	id := cmd.String("id", "", "remediation action UUID")
	reason := cmd.String("reason", "", "optional note")
	cmd.Parse(args)
	if *id == "" {
		fmt.Printf("Error: --id is required\n")
		os.Exit(1)
	}
	body, err := postRequest(config, "/api/v1/remediation/"+*id+"/"+verb, map[string]any{"reason": *reason})
	fail(err, "remediation "+verb)
	fmt.Println(body)
	if verb == "apply" && strings.Contains(body, "\"error\"") {
		os.Exit(exitcode.Violation)
	}
}
