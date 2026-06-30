// Fides Web Portal JS - Logic & REST Interactions

document.addEventListener("DOMContentLoaded", () => {
    // State management
    let state = {
        activeTab: "dashboard",
        orgs: [],
        flows: [],
        artifacts: [],
        environments: [],
        policies: [],
        attestations: [],
        llmAssessments: [],
        activeEnvId: null,
        activePolicyId: null,
        activeAssessmentId: null
    };

    // DOM Elements
    const navItems = document.querySelectorAll(".nav-item");
    const tabPanes = document.querySelectorAll(".tab-pane");
    const pageTitle = document.getElementById("page-title");
    const pageSubtitle = document.getElementById("page-subtitle");

    // Initialize UI Navigation
    navItems.forEach(item => {
        item.addEventListener("click", (e) => {
            e.preventDefault();
            const tabId = item.getAttribute("data-tab");
            
            navItems.forEach(i => i.classList.remove("active"));
            item.classList.add("active");
            
            tabPanes.forEach(pane => pane.classList.remove("active"));
            document.getElementById(`tab-${tabId}`).classList.add("active");
            
            state.activeTab = tabId;
            updateHeader(tabId);
            renderTabContent(tabId);
        });
    });

    // Header updates on navigation
    function updateHeader(tabId) {
        switch (tabId) {
            case "dashboard":
                pageTitle.textContent = "Compliance Overview";
                pageSubtitle.textContent = "Real-time status of software delivery pipelines and runtimes";
                break;
            case "flows":
                pageTitle.textContent = "Flows & Build Trails";
                pageSubtitle.textContent = "Trace code releases back to their pipelines and repositories";
                break;
            case "artifacts":
                pageTitle.textContent = "Artifact Registry";
                pageSubtitle.textContent = "Immutable catalog of software digests and Software Bills of Materials (SBOM)";
                break;
            case "environments":
                pageTitle.textContent = "Environment Snapshots";
                pageSubtitle.textContent = "Monitor running workloads, configurations, and active drift alerts";
                break;
            case "policies":
                pageTitle.textContent = "Compliance Policies";
                pageSubtitle.textContent = "Define gates, required controls, and evaluation rules for releases";
                break;
            case "ai-audits":
                pageTitle.textContent = "AI Audit Gateway";
                pageSubtitle.textContent = "Automated LLM assessments of vulnerability scans and logs";
                break;
            case "ai-assistant":
                pageTitle.textContent = "AI Compliance Copilot";
                pageSubtitle.textContent = "Manage compliance, generate flows, and audit release trails using natural language";
                break;
            case "settings":
                pageTitle.textContent = "System Settings";
                pageSubtitle.textContent = "Configure multi-tenancy, OAuth providers, cloud storage backends, and vaults";
                break;
        }
    }

    // Modal Events
    const flowModal = document.getElementById("modal-flow");
    const sbomModal = document.getElementById("modal-sbom");
    const openFlowModalBtn = document.getElementById("btn-create-flow-modal");
    const closeFlowModalBtn = document.getElementById("btn-close-flow-modal");
    const cancelFlowBtn = document.getElementById("btn-cancel-flow");
    const submitFlowBtn = document.getElementById("btn-submit-flow");

    if (openFlowModalBtn) {
        openFlowModalBtn.addEventListener("click", () => flowModal.classList.add("active"));
    }
    if (closeFlowModalBtn) {
        closeFlowModalBtn.addEventListener("click", () => flowModal.classList.remove("active"));
    }
    if (cancelFlowBtn) {
        cancelFlowBtn.addEventListener("click", () => flowModal.classList.remove("active"));
    }
    document.getElementById("btn-close-sbom-modal").addEventListener("click", () => sbomModal.classList.remove("active"));

    if (submitFlowBtn) {
        submitFlowBtn.addEventListener("click", async () => {
            const name = document.getElementById("flow-name").value;
            const desc = document.getElementById("flow-desc").value;
            
            if (!name) return alert("Flow name is required");

            const orgId = state.orgs[0]?.id || "5d57b8c7-4328-4e1b-93df-4161b9a918a3";

            try {
                const response = await fetch("/api/v1/flows", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: jsonStringify({
                        org_id: orgId,
                        name: name,
                        description: desc,
                        tags: {}
                    })
                });
                
                if (response.ok) {
                    flowModal.classList.remove("active");
                    document.getElementById("flow-name").value = "";
                    document.getElementById("flow-desc").value = "";
                    await loadData();
                    renderTabContent("flows");
                }
            } catch (err) {
                console.error("Failed to create flow:", err);
            }
        });
    }

    // Fetch API Data and bootstrap state
    async function loadData() {
        try {
            const [flowsResp, artsResp, envsResp, polsResp, aiResp] = await Promise.all([
                fetch("/api/v1/flows"),
                fetch("/api/v1/artifacts"),
                fetch("/api/v1/environments"),
                fetch("/api/v1/policies"),
                fetch("/api/v1/ai-assessments")
            ]);

            if (flowsResp.ok && artsResp.ok && envsResp.ok && polsResp.ok && aiResp.ok) {
                state.flows = await flowsResp.json() || [];
                state.artifacts = await artsResp.json() || [];
                state.environments = await envsResp.json() || [];
                state.policies = await polsResp.json() || [];
                state.llmAssessments = await aiResp.json() || [];
            }

            // Fallback to seeded mock data if database has no records (first-run visual preview)
            if (state.flows.length === 0 && state.environments.length === 0) {
                console.log("Empty database, seeding demo visual preview data...");
                seedMockData();
            } else {
                // Initialize active IDs
                if (state.environments.length > 0 && !state.activeEnvId) {
                    state.activeEnvId = state.environments[0].id;
                }
                if (state.policies.length > 0 && !state.activePolicyId) {
                    state.activePolicyId = state.policies[0].id;
                }
                if (state.llmAssessments.length > 0 && !state.activeAssessmentId) {
                    state.activeAssessmentId = state.llmAssessments[0].id;
                }
            }
        } catch (e) {
            console.log("Database connection error, using local fallback preview:", e);
            seedMockData();
        }
        
        calculateMetrics();
    }

    function calculateMetrics() {
        document.getElementById("stat-artifacts").textContent = state.artifacts.length;
        
        // Calculate compliance
        const totalTrails = state.artifacts.length;
        const compliantTrails = state.artifacts.filter(a => a.sbomStatus === "Compliant").length;
        const compPct = totalTrails > 0 ? Math.round((compliantTrails / totalTrails) * 100) : 100;
        document.getElementById("stat-compliant").textContent = `${compPct}%`;

        // Calculate drift & shadow counts
        let driftAndShadowAlerts = 0;
        state.environments.forEach(env => {
            driftAndShadowAlerts += env.drifts.length + env.shadowChanges.length;
        });
        document.getElementById("stat-alerts").textContent = driftAndShadowAlerts;
        document.getElementById("drift-count-badge").textContent = driftAndShadowAlerts;
        if (driftAndShadowAlerts === 0) {
            document.getElementById("drift-count-badge").style.display = "none";
        } else {
            document.getElementById("drift-count-badge").style.display = "inline-block";
        }

        document.getElementById("stat-ai").textContent = state.llmAssessments.length;
    }

    // Tab content router
    function renderTabContent(tabId) {
        switch (tabId) {
            case "dashboard":
                renderDashboard();
                break;
            case "flows":
                renderFlows();
                break;
            case "artifacts":
                renderArtifacts();
                break;
            case "environments":
                renderEnvironments();
                break;
            case "policies":
                renderPolicies();
                break;
            case "ai-audits":
                renderAIAudits();
                break;
            case "ai-assistant":
                renderAIAssistant();
                break;
            case "settings":
                renderSettings();
                break;
        }
    }

    // Render Dashboard
    function renderDashboard() {
        const envTableBody = document.querySelector("#env-summary-table tbody");
        envTableBody.innerHTML = "";

        state.environments.forEach(env => {
            const row = document.createElement("tr");
            const alertCount = env.drifts.length + env.shadowChanges.length;
            const statusClass = alertCount > 0 ? "danger" : "success";
            const statusText = alertCount > 0 ? "Non-Compliant" : "Compliant";

            row.innerHTML = `
                <td><strong>${env.name}</strong></td>
                <td><span class="badge btn-outline">${env.type}</span></td>
                <td>${env.lastSnapshot}</td>
                <td class="${env.drifts.length > 0 ? 'text-danger' : ''}">${env.drifts.length}</td>
                <td class="${env.shadowChanges.length > 0 ? 'text-danger' : ''}">${env.shadowChanges.length}</td>
                <td><span class="status-pill ${statusClass}">${statusText}</span></td>
            `;
            envTableBody.appendChild(row);
        });

        // Render Recent Timeline
        const timelineList = document.getElementById("recent-trails-list");
        timelineList.innerHTML = "";
        
        state.artifacts.slice(0, 4).forEach((art, idx) => {
            const item = document.createElement("div");
            item.className = "timeline-item";
            
            const isCompliant = art.sbomStatus === "Compliant";
            const iconClass = isCompliant ? "fa-circle-check text-success bg-success" : "fa-triangle-exclamation text-danger bg-danger";
            
            item.innerHTML = `
                <div class="timeline-icon"><i class="fa-solid ${iconClass}"></i></div>
                <div class="timeline-content">
                    <span class="timeline-title">Build attested: <strong>${art.name}</strong> (${art.trailName})</span>
                    <span class="subtitle">Fingerprint: <code>${art.sha256.substring(0, 16)}...</code></span>
                    <span class="timeline-time">${art.createdAt}</span>
                </div>
            `;
            timelineList.appendChild(item);
        });
    }

    // Render Flows
    function renderFlows() {
        const container = document.getElementById("flows-container");
        container.innerHTML = "";

        state.flows.forEach(flow => {
            const card = document.createElement("div");
            card.className = "flow-card";
            card.innerHTML = `
                <h3>${flow.name}</h3>
                <p>${flow.description}</p>
                <div class="flow-meta">
                    <span><i class="fa-solid fa-code-branch"></i> git-main</span>
                    <span>Created: ${flow.createdAt.substring(0, 10)}</span>
                </div>
            `;
            container.appendChild(card);
        });
    }

    // Render Artifacts
    function renderArtifacts() {
        const tableBody = document.querySelector("#artifacts-table tbody");
        tableBody.innerHTML = "";

        state.artifacts.forEach(art => {
            const row = document.createElement("tr");
            const statusClass = art.sbomStatus === "Compliant" ? "success" : "danger";
            
            row.innerHTML = `
                <td><strong>${art.name}</strong></td>
                <td><span class="badge btn-outline">${art.type}</span></td>
                <td><code>${art.sha256.substring(0, 24)}...</code></td>
                <td>${art.trailName}</td>
                <td>${art.createdAt}</td>
                <td>
                    <button class="btn btn-outline btn-sbom-view" data-sha="${art.sha256}" style="padding: 4px 10px; font-size: 12px;">
                        <i class="fa-solid fa-file-invoice"></i> View SBOM
                    </button>
                </td>
            `;
            tableBody.appendChild(row);
        });

        // Hook up view SBOM buttons
        document.querySelectorAll(".btn-sbom-view").forEach(btn => {
            btn.addEventListener("click", () => {
                const sha = btn.getAttribute("data-sha");
                openSBOMModal(sha);
            });
        });
    }

    function openSBOMModal(sha) {
        const art = state.artifacts.find(a => a.sha256 === sha);
        if (!art) return;

        document.getElementById("sbom-modal-title").textContent = `SBOM Package Inventory — ${art.name}`;
        document.getElementById("sbom-modal-sha").textContent = art.sha256;
        document.getElementById("sbom-modal-count").textContent = art.sbom.length;

        const tableBody = document.querySelector("#sbom-packages-table tbody");
        tableBody.innerHTML = "";

        art.sbom.forEach(pkg => {
            const row = document.createElement("tr");
            row.innerHTML = `
                <td><strong>${pkg.name}</strong></td>
                <td><code>${pkg.version}</code></td>
                <td>${pkg.license}</td>
                <td><span class="badge ${pkg.vulnerabilities === 'None' ? 'bg-success' : 'badge-alert'}">${pkg.vulnerabilities}</span></td>
            `;
            tableBody.appendChild(row);
        });

        sbomModal.classList.add("active");
    }

    // Render Environments
    function renderEnvironments() {
        const listGroup = document.getElementById("runtimes-list-group");
        listGroup.innerHTML = "";

        state.environments.forEach(env => {
            const item = document.createElement("div");
            item.className = `list-item ${state.activeEnvId === env.id ? 'active' : ''}`;
            item.innerHTML = `
                <span class="list-item-title">${env.name}</span>
                <span class="list-item-subtitle">Snapshot: ${env.lastSnapshot}</span>
            `;
            item.addEventListener("click", () => {
                state.activeEnvId = env.id;
                renderEnvironments();
            });
            listGroup.appendChild(item);
        });

        const activeEnv = state.environments.find(e => e.id === state.activeEnvId);
        if (!activeEnv) return;

        // Render environment details
        document.getElementById("env-details-title").textContent = activeEnv.name;
        const driftCount = activeEnv.drifts.length + activeEnv.shadowChanges.length;
        const detailsBadge = document.getElementById("env-details-badge");
        
        if (driftCount > 0) {
            detailsBadge.textContent = "Non-Compliant";
            detailsBadge.className = "badge badge-alert";
        } else {
            detailsBadge.textContent = "Compliant";
            detailsBadge.className = "badge bg-success";
        }

        document.getElementById("env-details-desc").textContent = activeEnv.description;

        // Render Running Artifacts table
        const tableBody = document.querySelector("#env-artifacts-table tbody");
        tableBody.innerHTML = "";

        activeEnv.running.forEach(run => {
            const provenName = run.registered ? run.name : "Unregistered (Shadow Deployment!)";
            const provenClass = run.registered ? "text-success" : "text-danger";
            const gateText = run.registered ? "Passing" : "Failed";
            const gateClass = run.registered ? "success" : "danger";

            row = document.createElement("tr");
            row.innerHTML = `
                <td><strong>${run.service}</strong></td>
                <td><code>${run.sha256.substring(0, 24)}...</code></td>
                <td class="${provenClass}"><strong>${provenName}</strong></td>
                <td><span class="status-pill ${gateClass}">${gateText}</span></td>
            `;
            tableBody.appendChild(row);
        });

        // Render drifts alerts list
        const driftsContainer = document.getElementById("env-drifts-container");
        driftsContainer.innerHTML = "";

        if (driftCount === 0) {
            driftsContainer.innerHTML = `
                <div style="color: var(--color-text-secondary); text-align: center; padding: 20px;">
                    <i class="fa-solid fa-circle-check text-success" style="font-size: 24px; margin-bottom: 10px; display: block;"></i>
                    No drifts or shadow changes detected in this environment.
                </div>
            `;
        } else {
            activeEnv.shadowChanges.forEach(sc => {
                const card = document.createElement("div");
                card.className = "drift-alert-card";
                card.innerHTML = `
                    <i class="fa-solid fa-ghost"></i>
                    <span><strong>SHADOW CHANGE:</strong> ${sc}</span>
                `;
                driftsContainer.appendChild(card);
            });

            activeEnv.drifts.forEach(dr => {
                const card = document.createElement("div");
                card.className = "drift-alert-card";
                card.style.background = "var(--warning-bg)";
                card.style.borderColor = "rgba(245, 158, 11, 0.25)";
                card.style.color = "#fef3c7";
                card.innerHTML = `
                    <i class="fa-solid fa-clock-rotate-left"></i>
                    <span><strong>CONFIGURATION DRIFT:</strong> ${dr}</span>
                `;
                driftsContainer.appendChild(card);
            });
        }
    }

    // Render Policies
    function renderPolicies() {
        const listGroup = document.getElementById("policy-list-group");
        listGroup.innerHTML = "";

        state.policies.forEach(pol => {
            const item = document.createElement("div");
            item.className = `list-item ${state.activePolicyId === pol.id ? 'active' : ''}`;
            item.innerHTML = `
                <span class="list-item-title">${pol.name}</span>
                <span class="list-item-subtitle">Target: ${pol.target}</span>
            `;
            item.addEventListener("click", () => {
                state.activePolicyId = pol.id;
                renderPolicies();
            });
            listGroup.appendChild(item);
        });

        const activePolicy = state.policies.find(p => p.id === state.activePolicyId);
        const editor = document.getElementById("policy-yaml-editor");
        
        if (activePolicy) {
            editor.value = activePolicy.yaml;
            document.getElementById("policy-title").textContent = `Policy Rules — ${activePolicy.name}`;
        }
    }

    // Render AI Audits
    function renderAIAudits() {
        const container = document.getElementById("ai-logs-container");
        container.innerHTML = "";

        state.llmAssessments.forEach(ass => {
            const item = document.createElement("div");
            item.className = `list-item ${state.activeAssessmentId === ass.id ? 'active' : ''}`;
            
            const isCompliant = ass.complianceScore >= 70;
            const badgeClass = isCompliant ? "bg-success" : "badge-alert";
            const badgeText = isCompliant ? "SAFE" : "RISK";

            item.innerHTML = `
                <div style="display: flex; justify-content: space-between; width: 100%;">
                    <span class="list-item-title">${ass.attestationName}</span>
                    <span class="badge ${badgeClass}">${badgeText}</span>
                </div>
                <span class="list-item-subtitle">Score: ${ass.complianceScore}/100</span>
            `;
            item.addEventListener("click", () => {
                state.activeAssessmentId = ass.id;
                renderAIAudits();
            });
            container.appendChild(item);
        });

        const activeAss = state.llmAssessments.find(a => a.id === state.activeAssessmentId);
        if (!activeAss) return;

        // Render assessment details
        document.getElementById("ai-title").textContent = `Audit Risk Evaluation — ${activeAss.attestationName}`;
        document.getElementById("ai-model-info").textContent = `${activeAss.modelProvider} (${activeAss.modelName})`;
        document.getElementById("ai-date-info").textContent = activeAss.createdAt;
        
        const gauge = document.getElementById("ai-gauge");
        gauge.textContent = activeAss.complianceScore;
        
        if (activeAss.complianceScore >= 80) {
            gauge.style.background = "var(--color-success)";
        } else if (activeAss.complianceScore >= 50) {
            gauge.style.background = "var(--color-warning)";
        } else {
            gauge.style.background = "var(--color-danger)";
        }

        // Render markdown body
        document.getElementById("ai-markdown-content").innerHTML = formatMarkdown(activeAss.assessmentRaw);
    }

    function formatMarkdown(text) {
        // Simple regex-based markdown formatter for preview
        return text
            .replace(/\n\n/g, "<br/><br/>")
            .replace(/\* \*\*(.*?)\*\*/g, "<li><strong>$1</strong>")
            .replace(/\* (.*?)/g, "<li>$1")
            .replace(/### (.*?)/g, "<h3>$1</h3>")
            .replace(/## (.*?)/g, "<h2>$1</h2>")
            .replace(/COMPLIANCE_SCORE: (.*?)/g, "<p><strong>Verdict Score: $1/100</strong></p>");
    }

    // Helper helper
    function jsonStringify(obj) {
        return JSON.stringify(obj, null, 2);
    }

    // Seed mock data
    function seedMockData() {
        state.orgs = [{ id: "5d57b8c7-4328-4e1b-93df-4161b9a918a3", name: "Payments Team" }];

        state.flows = [
            { id: "f83b3e8c-8dc7-4a0b-ae95-716d1ba1f122", name: "auth-service", description: "CI/CD flow for authorization endpoints", createdAt: "2026-06-25T12:00:00Z" },
            { id: "e102f30c-cd14-411a-8ce4-55cc28172901", name: "payment-gateway", description: "CI/CD pipeline for card processing backend", createdAt: "2026-06-28T09:30:00Z" }
        ];

        state.artifacts = [
            {
                sha256: "b1d830f367e9154ec5a6dc8634c01d6706e23b20757d59850c90c01067e23b20",
                name: "auth-service",
                type: "docker",
                trailName: "build-142",
                createdAt: "2026-06-30 07:12:00",
                sbomStatus: "Compliant",
                sbom: [
                    { name: "libc-bin", version: "2.36-9", license: "LGPL-2.1", vulnerabilities: "None" },
                    { name: "openssl", version: "3.0.8-1", license: "Apache-2.0", vulnerabilities: "None" },
                    { name: "go-uuid", version: "1.6.0", license: "BSD-3-Clause", vulnerabilities: "None" }
                ]
            },
            {
                sha256: "8e7a63b2c154ec5a6dc8634c01d6706e23b20757d59850c90c01067e23a31",
                name: "payment-gateway",
                type: "docker",
                trailName: "build-98",
                createdAt: "2026-06-29 18:40:00",
                sbomStatus: "Non-Compliant",
                sbom: [
                    { name: "libcrypto3", version: "3.0.7-1", license: "Apache-2.0", vulnerabilities: "1 High CVE-2023-0286" },
                    { name: "readline", version: "8.2-1.3", license: "GPL-3.0", vulnerabilities: "None" }
                ]
            }
        ];

        state.environments = [
            {
                id: "env-prod-k8s",
                name: "Production K8s",
                type: "K8S",
                lastSnapshot: "2026-06-30 08:00:00",
                description: "Primary production cluster hosted on AWS EKS",
                running: [
                    { service: "auth-service", sha256: "b1d830f367e9154ec5a6dc8634c01d6706e23b20757d59850c90c01067e23b20", registered: true, name: "auth-service" }
                ],
                drifts: [],
                shadowChanges: []
            },
            {
                id: "env-prod-ecs",
                name: "Production ECS Host",
                type: "ECS",
                lastSnapshot: "2026-06-30 08:15:00",
                description: "Fargate container host for transactional tasks",
                running: [
                    { service: "payment-gateway", sha256: "8e7a63b2c154ec5a6dc8634c01d6706e23b20757d59850c90c01067e23a31", registered: true, name: "payment-gateway" },
                    { service: "unregistered-daemon", sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", registered: false, name: "" }
                ],
                drifts: [
                    "payment-gateway running artifact has failing scan attestations (CVEs present)"
                ],
                shadowChanges: [
                    "unregistered-daemon running image digest has no build trail registration (Shadow Deployment!)"
                ]
            }
        ];

        state.policies = [
            {
                id: "pol-prod",
                name: "production-release-rules",
                target: "Production environments",
                yaml: `_schema: https://docs.fides.com/schemas/policy/v1\n\nartifacts:\n  provenance:\n    required: true # Must exist in registry\n\n  attestations:\n    - name: unit-tests\n      type: junit\n      rules:\n        - ".failures == 0"\n        - ".errors == 0"\n\n    - name: snyk-scan\n      type: vulnerability-scan\n      rules:\n        - ".vulnerabilities.critical == 0"\n\n    - name: secret-scan\n      type: secret-scan\n      rules:\n        - ".leaks == 0"`
            }
        ];

        state.llmAssessments = [
            {
                id: "ass-1",
                attestationName: "SBOM Scan Evaluation",
                modelProvider: "Ollama",
                modelName: "llama3:8b",
                createdAt: "2026-06-30 07:15:00",
                complianceScore: 95,
                assessmentRaw: `### Fides-AI Audit Evaluation Report\n\n* **SBOM Package Count**: 3 packages scanned.\n* **Licence Auditing**: Verified LGPL-2.1, Apache-2.0, and BSD-3-Clause. All packages comply with corporate legal guidelines.\n* **Risk assessment**: No vulnerable package dependencies discovered.\n\nCOMPLIANCE_SCORE: 95`
            },
            {
                id: "ass-2",
                attestationName: "Secret Leak Scan Assessment",
                modelProvider: "Ollama",
                modelName: "llama3:8b",
                createdAt: "2026-06-29 18:42:00",
                complianceScore: 40,
                assessmentRaw: `### Fides-AI Audit Evaluation Report\n\n* **Exposed credentials**: Found 1 high-risk secret in code base.\n* **Analysis**: Gitleaks reported an AWS Client Access Secret key checked into file \`config/secrets.go\` on line 12. This key is active and poses significant danger.\n* **Recommendation**: Immediate secret rotation required. Add secrets.go to gitignore.\n\nCOMPLIANCE_SCORE: 40`
            }
        ];

        // Set defaults
        state.activeEnvId = state.environments[0].id;
        state.activePolicyId = state.policies[0].id;
        state.activeAssessmentId = state.llmAssessments[0].id;
    }

    // Check if redirected from a successful OAuth simulation
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get("login") === "success") {
        const providerName = urlParams.get("provider");
        alert("Authentication Successful via SSO Provider: " + providerName.toUpperCase() + "\nTenant Organization context verified.");
        // Clear url params
        window.history.replaceState({}, document.title, "/");
    }

    // Policy Wizard Generator Action
    const generateWizardBtn = document.getElementById("btn-generate-wizard");
    if (generateWizardBtn) {
        generateWizardBtn.addEventListener("click", async () => {
            const framework = document.getElementById("wizard-framework").value;
            const desc = document.getElementById("wizard-desc").value;

            if (!desc) {
                alert("Please describe your compliance requirements first");
                return;
            }

            generateWizardBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Generating...';
            generateWizardBtn.disabled = true;

            try {
                const response = await fetch("/api/v1/ai/generate-policy", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ framework: framework, description: desc })
                });

                if (response.ok) {
                    const data = await response.json();
                    const editor = document.getElementById("policy-yaml-editor");
                    editor.value = JSON.stringify(data, null, 2);
                } else {
                    alert("Failed to generate policy from LLM: " + response.statusText);
                }
            } catch (err) {
                console.error(err);
                alert("Error calling LLM policy wizard");
            } finally {
                generateWizardBtn.innerHTML = '<i class="fa-solid fa-brain"></i> Generate JQ Rules';
                generateWizardBtn.disabled = false;
            }
        });
    }

    // AI Assistant Conversational Engine
    state.chatHistory = [];

    function appendMessage(role, text) {
        const box = document.getElementById("chat-messages-box");
        if (!box) return;
        
        const msgDiv = document.createElement("div");
        msgDiv.className = `message ${role}`;
        
        let htmlContent = text
            .replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>")
            .replace(/\*(.*?)\*/g, "<em>$1</em>")
            .replace(/`(.*?)`/g, "<code>$1</code>")
            .replace(/\n/g, "<br>");
            
        msgDiv.innerHTML = `<div class="msg-bubble">${htmlContent}</div>`;
        box.appendChild(msgDiv);
        box.scrollTop = box.scrollHeight;
    }

    async function sendChatQuery(msgText) {
        if (!msgText.trim()) return;
        
        appendMessage("user", msgText);
        
        const box = document.getElementById("chat-messages-box");
        const typingDiv = document.createElement("div");
        typingDiv.className = "message system typing-indicator";
        typingDiv.innerHTML = `<div class="msg-bubble"><i class="fa-solid fa-ellipsis fa-bounce"></i> Copilot is thinking...</div>`;
        box.appendChild(typingDiv);
        box.scrollTop = box.scrollHeight;

        try {
            const response = await fetch("/api/v1/ai/chat", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    message: msgText,
                    history: state.chatHistory
                })
            });

            typingDiv.remove();

            if (response.ok) {
                const data = await response.json();
                appendMessage("assistant", data.response);
                state.chatHistory.push({ role: "user", content: msgText });
                state.chatHistory.push({ role: "assistant", content: data.response });
            } else {
                appendMessage("assistant", "I encountered an error executing this request: " + response.statusText);
            }
        } catch (err) {
            typingDiv.remove();
            appendMessage("assistant", "Unable to establish communication with the Fides AI backend.");
            console.error(err);
        }
    }

    const btnSendChat = document.getElementById("btn-send-chat");
    const chatUserInput = document.getElementById("chat-user-input");

    if (btnSendChat && chatUserInput) {
        btnSendChat.addEventListener("click", () => {
            const text = chatUserInput.value;
            chatUserInput.value = "";
            sendChatQuery(text);
        });

        chatUserInput.addEventListener("keypress", (e) => {
            if (e.key === "Enter") {
                const text = chatUserInput.value;
                chatUserInput.value = "";
                sendChatQuery(text);
            }
        });
    }

    const btnClearChat = document.getElementById("btn-clear-chat");
    if (btnClearChat) {
        btnClearChat.addEventListener("click", () => {
            state.chatHistory = [];
            const box = document.getElementById("chat-messages-box");
            if (box) {
                box.innerHTML = `
                    <div class="message system">
                        <div class="msg-bubble">
                            Chat history cleared. How can I help you manage compliance pipelines today?
                        </div>
                    </div>
                `;
            }
        });
    }

    window.sendSuggestion = function(text) {
        sendChatQuery(text);
    };

    const chipCreateFlow = document.getElementById("chip-create-flow");
    const chipListFlows = document.getElementById("chip-list-flows");
    const chipFailingTrails = document.getElementById("chip-failing-trails");

    if (chipCreateFlow) chipCreateFlow.addEventListener("click", () => sendChatQuery("create flow payments-ingress"));
    if (chipListFlows) chipListFlows.addEventListener("click", () => sendChatQuery("list flows"));
    if (chipFailingTrails) chipFailingTrails.addEventListener("click", () => sendChatQuery("find failing trails"));

    function renderAIAssistant() {
        const box = document.getElementById("chat-messages-box");
        if (box) box.scrollTop = box.scrollHeight;
    }

    const storageDriverSelector = document.getElementById("setting-storage-driver");
    if (storageDriverSelector) {
        storageDriverSelector.addEventListener("change", () => {
            const driver = storageDriverSelector.value;
            const endpointGrp = document.getElementById("group-s3-endpoint");
            const keysGrp = document.getElementById("group-s3-access-path");
            const secretGrp = document.getElementById("group-s3-secret-path");
            const regionGrp = document.getElementById("group-s3-region");

            if (driver === "local") {
                if (endpointGrp) endpointGrp.style.display = "none";
                if (keysGrp) keysGrp.style.display = "none";
                if (secretGrp) secretGrp.style.display = "none";
                if (regionGrp) regionGrp.style.display = "none";
            } else {
                if (endpointGrp) endpointGrp.style.display = "block";
                if (keysGrp) keysGrp.style.display = "block";
                if (secretGrp) secretGrp.style.display = "block";
                if (regionGrp) regionGrp.style.display = "block";
            }
        });
    }

    const btnSsoTest = document.getElementById("btn-setting-sso-test");
    if (btnSsoTest) {
        btnSsoTest.addEventListener("click", () => {
            const provider = document.getElementById("setting-sso-provider").value;
            const orgId = state.orgs[0]?.id || "5d57b8c7-4328-4e1b-93df-4161b9a918a3";
            window.location.href = `/api/v1/auth/login?org_id=${orgId}&provider=${provider}`;
        });
    }

    async function renderSettings() {
        const orgId = state.orgs[0]?.id || "5d57b8c7-4328-4e1b-93df-4161b9a918a3";
        try {
            const response = await fetch(`/api/v1/tenant/settings?org_id=${orgId}`);
            if (response.ok) {
                const settings = await response.json();
                
                if (settings.auth) {
                    document.getElementById("setting-sso-provider").value = settings.auth.provider_name || "github";
                    document.getElementById("setting-sso-client-id").value = settings.auth.client_id || "";
                    document.getElementById("setting-sso-secret-path").value = settings.auth.client_secret_path || "";
                    document.getElementById("setting-sso-redirect").value = settings.auth.redirect_uri || "";
                    document.getElementById("setting-sso-enabled").checked = settings.auth.enabled;
                }
                
                if (settings.storage) {
                    document.getElementById("setting-storage-driver").value = settings.storage.storage_driver || "local";
                    document.getElementById("setting-storage-endpoint").value = settings.storage.s3_endpoint || "";
                    document.getElementById("setting-storage-bucket").value = settings.storage.s3_bucket || "fides-evidence";
                    document.getElementById("setting-storage-access-path").value = settings.storage.s3_access_key_path || "";
                    document.getElementById("setting-storage-secret-path").value = settings.storage.s3_secret_key_path || "";
                    document.getElementById("setting-storage-region").value = settings.storage.s3_region || "us-east-1";
                    
                    if (storageDriverSelector) storageDriverSelector.dispatchEvent(new Event("change"));
                }
                
                if (settings.vault) {
                    document.getElementById("setting-vault-provider").value = settings.vault.vault_provider || "env";
                    document.getElementById("setting-vault-address").value = settings.vault.vault_address || "";
                    document.getElementById("setting-vault-token-path").value = settings.vault.vault_token_path || "";
                    document.getElementById("setting-vault-role").value = settings.vault.vault_role || "";
                }
            }
        } catch (err) {
            console.error("Failed to load tenant settings", err);
        }
    }

    const btnSaveSettings = document.getElementById("btn-save-settings");
    if (btnSaveSettings) {
        btnSaveSettings.addEventListener("click", async () => {
            const orgId = state.orgs[0]?.id || "5d57b8c7-4328-4e1b-93df-4161b9a918a3";
            const statusMsg = document.getElementById("settings-status-message");

            btnSaveSettings.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Saving...';
            btnSaveSettings.disabled = true;

            const payload = {
                org_id: orgId,
                auth: {
                    provider_name: document.getElementById("setting-sso-provider").value,
                    client_id: document.getElementById("setting-sso-client-id").value,
                    client_secret_path: document.getElementById("setting-sso-secret-path").value,
                    redirect_uri: document.getElementById("setting-sso-redirect").value,
                    enabled: document.getElementById("setting-sso-enabled").checked
                },
                storage: {
                    storage_driver: document.getElementById("setting-storage-driver").value,
                    s3_endpoint: document.getElementById("setting-storage-endpoint").value,
                    s3_bucket: document.getElementById("setting-storage-bucket").value,
                    s3_access_key_path: document.getElementById("setting-storage-access-path").value,
                    s3_secret_key_path: document.getElementById("setting-storage-secret-path").value,
                    s3_region: document.getElementById("setting-storage-region").value
                },
                vault: {
                    vault_provider: document.getElementById("setting-vault-provider").value,
                    vault_address: document.getElementById("setting-vault-address").value,
                    vault_token_path: document.getElementById("setting-vault-token-path").value,
                    vault_role: document.getElementById("setting-vault-role").value
                }
            };

            try {
                const response = await fetch("/api/v1/tenant/settings", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(payload)
                });

                if (response.ok) {
                    statusMsg.textContent = "Configuration successfully saved and secured in database.";
                    setTimeout(() => statusMsg.textContent = "", 4000);
                } else {
                    alert("Failed to save settings: " + response.statusText);
                }
            } catch (err) {
                console.error(err);
                alert("Error saving settings configuration.");
            } finally {
                btnSaveSettings.innerHTML = '<i class="fa-solid fa-save"></i> Save Configuration';
                btnSaveSettings.disabled = false;
            }
        });
    }

    // Startup bootstrap
    loadData().then(() => {
        renderTabContent("dashboard");
    });
});
