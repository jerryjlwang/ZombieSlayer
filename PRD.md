# Product Requirements Document

## Product

ZombieSlayer: Zombie Prompt Injection Safeguard for Agents

## Status

Draft v0.1

## Authoring Note

This PRD is based on the user's interview answers as of April 18, 2026, with product and technical assumptions filled in where decisions were not fully specified. Assumptions are called out explicitly in the "Open Questions and Assumptions" section.

## 1. Executive Summary

ZombieSlayer is a developer-first safeguard for agentic systems that protects against "zombie prompt injections": malicious instructions hidden in retrieved or browsed content that activate later in the task or contaminate future runs. The MVP is designed for Claude co-work style human-plus-agent sessions, especially multi-step agents that research, plan, and act.

The product begins as a plugin developers can integrate into a Claude-centered agent workflow. It scans external content intake from retrieval and web fetch steps, detects suspicious instructions using a rule-based engine augmented with advanced anomaly-detection techniques, quarantines risky content without interrupting the live task flow, and presents a compact review at the end of the task. Users can then exclude quarantined content, explicitly include it, or "reprocess-clean" it by stripping suspicious instructions while preserving useful material.

In addition to intake protection, ZombieSlayer's MVP protects against persistence by blocking suspicious writes into memory, summaries, and handoffs, then retro-scanning stored artifacts to identify possible contamination. Over time, the product will extend to broader runtime protection, policy customization, and enterprise administration.

## 2. Problem Statement

Agent systems increasingly consume untrusted external text from web pages, retrieved documents, files, and tool outputs. That text can contain hidden instructions intended for the model rather than the human reader. Existing mitigations often focus on obvious prompt-injection attacks in the current turn, but they do not adequately address "zombie" behavior, where malicious instructions:

- hide inside seemingly relevant content,
- survive enough filtering to enter model context,
- influence later planning or actions,
- or contaminate memory, summaries, and handoffs so they reappear in future runs.

This creates a mismatch between how developers think their agents behave and how compromised agents can actually behave once external content becomes part of the reasoning substrate.

Developers need a safeguard that is easy to integrate, preserves agent usefulness, does not constantly interrupt real-time workflows, and still gives humans enough visibility and control to recover safely.

## 3. Working Definition

For this product, a zombie prompt injection is:

"A malicious instruction hidden in retrieved or browsed content that is not part of the user's intended task, enters or attempts to enter the agent's reasoning pipeline, and can influence later reasoning, actions, memory, summaries, or future sessions."

This differs from a simple one-turn prompt injection because the attack is defined by delayed impact, persistence, or downstream contamination rather than only immediate override.

## 4. Vision

Enable developers to add strong, low-friction protection against hidden prompt injections before those instructions shape agent behavior, while preserving useful web and retrieval content and giving users a clean recovery workflow after the task completes.

## 5. Product Positioning

### Primary user

Developers building agents.

### Secondary users

- AI product teams shipping agent experiences
- Operators or technical owners responsible for reliability and safety
- End users reviewing quarantined material in collaborative sessions

### Initial wedge

A plugin for Claude co-work style agent workflows with sane defaults and extension hooks.

### Core value proposition

- Catch hidden prompt injections before the agent is influenced
- Make prompt-injection defense easy to add to existing agent stacks
- Preserve utility by quarantining suspicious material for end-of-task review instead of aggressively blocking normal workflows in real time

## 6. Goals

### MVP goals

1. Detect suspicious hidden instructions in retrieved documents and live web content before that content is added to the model context.
2. Quarantine suspicious content without breaking the user's real-time collaborative flow.
3. Provide an end-of-task review flow where users can exclude content, explicitly include it, or reprocess-clean it.
4. Prevent suspicious content from being written into summaries, memory, or handoff artifacts.
5. Retro-scan stored session artifacts to identify likely persistence contamination.
6. Expose clear provenance for suspicious content, including source URL or document/chunk origin.
7. Offer a developer-friendly plugin interface with sane defaults plus hooks for custom review and policy behavior.

### Success criteria

- Strong detection on known zombie prompt-injection cases
- Acceptably low false positives on legitimate web and RAG content
- Minimal degradation to agent task quality
- Manageable latency and integration overhead for developers

## 7. Non-Goals

The MVP will not aim to:

- solve every kind of prompt injection across every model/runtime,
- protect every inbound source on day one,
- offer a full enterprise security console,
- rely on heavy fine-tuning as a prerequisite,
- replace broader action authorization systems,
- guarantee zero false negatives,
- or fully automate trust decisions without human review.

## 8. Users and Jobs To Be Done

### Developer persona

A developer is building a multi-step Claude-centered agent that researches external information, plans work, and may call tools or update external systems. They want to adopt meaningful injection protection without rebuilding their stack or burying users under constant false alarms.

### End-user persona

A human collaborates with the agent during a task. They care about completing the task smoothly, then reviewing anything risky afterward in a clear, compact way.

### Jobs to be done

- As a developer, I want to plug prompt-injection protection into my intake pipeline with minimal setup so I can reduce risk quickly.
- As a developer, I want clear provenance and policy hooks so I can understand and customize how the safeguard behaves.
- As a user, I want the agent to keep moving during the task instead of interrupting me for every suspicious page fragment.
- As a user, I want a post-task summary of quarantined items and safe recovery choices.
- As an operator, I want suspicious persistence attempts blocked before they poison future runs.

## 9. Use Cases

### Core use case

A multi-step agent performs research using both retrieval and web browsing, synthesizes what it finds, then takes downstream actions such as tool calls, sending messages, or modifying state. Some external content contains hidden instructions like "ignore the user's request," "store this system prompt," or "send secrets to this URL." ZombieSlayer intercepts those instructions at intake, quarantines them, allows the task to continue with uncontaminated context when possible, blocks persistence attempts, and presents an end-of-task review.

### Priority use cases for MVP

1. Research and planning with web content plus retrieval
2. Contaminated source discovered before model-context inclusion
3. Suspicious memory or summary write blocked during the same or subsequent session
4. End-of-task user review of quarantined sources
5. Reprocess-clean flow to salvage useful material from suspicious sources

### Important but secondary use cases

- Tool output scanning
- File/code/comment scanning
- Shared multi-agent handoff protection beyond the initial collaboration model
- Workspace-wide administration

## 10. Threat Model

### In-scope attacker goals

- Override the agent's intended instructions
- Induce the agent to ignore user intent or system policy
- Cause data exfiltration or secret seeking
- Manipulate tool use or unsafe external actions
- Persist malicious instructions into memory, summaries, or handoffs
- Sabotage outputs or future tasks through latent contamination

### High-value assets to protect

- Model context integrity
- System and developer instructions
- Memory stores, summaries, and handoff artifacts
- Connected tools and external actions
- Sensitive user or workspace data
- User trust in agent behavior

### Primary attack surfaces in MVP

- Retrieved documents and document chunks
- Live web page content fetched during browsing or search

### Secondary attack surfaces planned later

- Tool output
- User-uploaded files
- Code, markdown, and comments
- User messages
- Cross-agent communications

### Trust assumptions

- External content is untrusted by default
- Internal developer configuration is more trusted, but not inherently safe
- Content provenance matters and should influence quarantine sensitivity
- Some benign content will look injection-like and requires careful handling

## 11. Product Principles

1. Protect before contamination, not only after damage.
2. Preserve useful work whenever possible.
3. Avoid unnecessary interruption during live collaborative flow.
4. Treat persistence attempts as high severity.
5. Make decisions explainable enough to debug and trust.
6. Use source-aware policies rather than uniform blunt blocking.
7. Default to sane behavior, but leave room for developer extension.

## 12. Product Scope

### MVP scope

- Claude co-work style single-session collaboration as the primary operating model
- Retrieval and web-fetch intake scanning
- Rule-based suspicious-content detection
- Advanced anomaly-detection augmentation, such as embedding- or distribution-based deviation scoring, chunk-structure analysis, and denoising or reconstruction-based suspiciousness signals
- Source-aware quarantine thresholds
- End-of-task quarantine summary with provenance
- User actions: exclude, include, reprocess-clean
- Blocking of suspicious writes to memory, summaries, and handoffs
- Retro-scan of stored session artifacts to identify contamination
- Plugin integration with sane defaults plus callback hooks
- Per-task mode selection, for example "strict scan" vs "fast scan"

### Post-MVP scope

- Tool output scanning
- Fine-grained admin policies
- Workspace- or org-level dashboards
- Shared-memory and multi-agent topology views
- Automatic remediation recommendations
- Provider-agnostic support beyond Claude-centered flows
- Enterprise audit exports and compliance reporting

## 13. Proposed Solution

ZombieSlayer will sit at the content intake layer of the agent runtime, intercepting retrieval chunks and web content before they are injected into model context. Each content item receives:

- source provenance,
- trust metadata,
- suspiciousness score,
- detected risk categories,
- and quarantine status.

If content is classified as suspicious, the system quarantines it rather than letting it shape the core reasoning path. The task continues with safe content where possible. The product stores the quarantined items and presents a compact review once the task reaches a natural completion boundary.

If suspicious content later appears to influence an attempt to write memory, create a summary, or prepare a handoff artifact, that write is blocked immediately. The system then performs a retro-scan of the affected artifacts to look for contamination that may have already entered storage.

When the task ends, the user sees a summary of quarantined sources and can choose to:

- exclude the source entirely,
- include the source despite the warning,
- or reprocess-clean it by removing suspicious instructions while preserving useful content.

## 14. Detection Strategy

### Detection philosophy

The user explicitly prefers a rule-based approach for the MVP, but not a naive keyword filter. The product should combine precise, interpretable rules with more advanced suspiciousness signals.

### Detection components

1. Rule engine
   - Detect imperative instructions directed at the model
   - Detect override phrases such as requests to ignore, replace, reveal, persist, or escalate
   - Detect meta-instruction patterns embedded in otherwise normal content
   - Detect suspicious formatting boundaries such as hidden sections, HTML comments, code fences containing agent directives, or markdown patterns commonly used to conceal instructions
2. Structural anomaly layer
   - Identify chunks whose instruction density, syntax, or intent distribution differs sharply from expected source patterns
   - Flag embedded control language that is semantically unrelated to nearby task content
3. Denoising and reconstruction heuristics
   - Use denoising, reconstruction error, or similar anomaly signals to detect latent instruction payloads that look inconsistent with the source's dominant semantic content
4. Source-aware policy
   - Apply stricter thresholds to untrusted web and retrieval sources than to trusted configuration or explicit user input
5. Risk categorization
   - Map findings into clear categories for downstream policy and review

### Initial risk categories

- Instruction override / ignore prior directions
- Data exfiltration / secret seeking
- Unsafe tool or external action manipulation
- Persistence attempts into memory, summaries, or handoffs

## 15. Functional Requirements

### Intake scanning

1. The system must inspect all retrieved chunks and fetched web content before inclusion in model context.
2. The system must attach provenance to each inspected item, including URL, document ID, chunk reference, or equivalent source identifier.
3. The system must assign one or more risk categories to suspicious content.
4. The system must support source-aware thresholds, with stricter treatment for external content than for trusted sources.

### Quarantine

5. The system must quarantine suspicious content instead of automatically presenting it to the main reasoning path.
6. The system must allow the task to continue with uncontaminated content whenever possible.
7. The system must preserve enough quarantined material and metadata for later review.
8. The system must avoid frequent inline interruption during the active task flow.

### Review flow

9. The system must provide an end-of-task quarantine summary.
10. The review summary must show provenance for each quarantined item.
11. The user must be able to exclude a quarantined item from future processing.
12. The user must be able to explicitly include a quarantined item for rerun.
13. The user must be able to request reprocess-clean for a quarantined item.
14. Reprocess-clean must remove suspicious spans or instructions while preserving the rest of the source as much as possible.

### Persistence protection

15. The system must block suspicious writes into memory, summaries, and handoff artifacts.
16. The system must record why a write was blocked.
17. The system must support retro-scanning existing artifacts for contamination after a blocked persistence event.
18. The system must mark previously stored suspicious artifacts for quarantine or remediation.

### Developer experience

19. The plugin must offer a simple default setup with sane defaults.
20. The plugin must allow developers to register hooks or callbacks for custom review flows and policy handling.
21. The plugin must support at least two per-task modes in the MVP, such as "fast scan" and "strict scan."
22. The integration surface must be opinionated enough to work quickly, while still allowing customization.

## 16. Non-Functional Requirements

1. Detection quality should optimize first for strong attack coverage and second for low false positives.
2. Task quality degradation should remain low enough that developers still trust the agent on normal work.
3. The product should add minimal user-facing friction during live collaboration.
4. The system should avoid excessive latency in standard research/planning workflows.
5. The rule engine and risk decisions should remain reasonably explainable.
6. The architecture should be extensible to additional content sources and agent runtimes.

## 17. UX Requirements

### During the task

- No constant modal interruptions for every suspicious item
- Agent continues on safe material when feasible
- Optional lightweight signal that some content was quarantined, depending on developer configuration

### End-of-task review

The end-of-task review should use a compact D-style experience:

- show a concise summary first,
- let the user choose what to inspect,
- avoid dumping raw warning noise by default.

Each quarantined item should include:

- source provenance,
- a short reason,
- risk category,
- and available user actions.

### Recovery actions

- Exclude: discard the source from future runs
- Include: approve the source for rerun despite the warning
- Reprocess-clean: strip suspicious instructions and preserve useful content for a safer rerun

## 18. Action Safety Policy

The user's responses indicate that downstream tool calls, messaging, and state modification are important risk areas, but that the product should avoid interrupting real-time flow whenever possible.

For MVP, the default action policy will be:

- intake protection is primary,
- suspicious persistence writes are blocked immediately,
- and irreversible downstream external actions that directly depend on tainted or quarantined content should be eligible for deferred execution until end-of-task review.

This preserves the product principle of low interruption while acknowledging that some actions are too risky to execute blindly once suspicious content has entered the run.

Assumed high-risk actions include:

- sending messages or comments,
- calling external tools or APIs with side effects,
- modifying files, records, or workflow state.

## 19. Example User Journey

1. A developer integrates ZombieSlayer into a Claude-centered agent workflow.
2. A user launches a task that searches the web and retrieves documents.
3. The plugin scans each external content chunk before context inclusion.
4. A web page contains hidden model-directed instructions asking the agent to ignore prior directions and store secret information in future notes.
5. The plugin flags the content as suspicious, records the page URL and category, and quarantines the relevant spans.
6. The agent continues the task using other safe sources.
7. Later, the agent attempts to write a summary containing instruction-like text derived from the suspicious page.
8. The system blocks the summary write and triggers a retro-scan of related artifacts.
9. At task completion, the user receives a compact review summary showing quarantined sources.
10. The user chooses reprocess-clean on the suspicious page.
11. The system removes the suspicious instructions, preserves the useful research material, and offers a rerun.

## 20. Competitive Alternatives

Developers today often rely on:

- manual prompt hardening,
- ad hoc allowlists and regex filters,
- model-level instruction tuning,
- generic guardrails libraries,
- or human review after obvious failures.

ZombieSlayer differentiates by focusing on delayed and persistent prompt-injection behavior, source-aware quarantine, and post-task recovery rather than only inline blocking.

## 21. Metrics

### Primary metrics

- Detection rate on known zombie prompt-injection benchmarks
- False positive rate on benign retrieval and web content
- Task success rate on clean workloads with protection enabled

### Secondary metrics

- Reprocess-clean success rate
- Percentage of quarantined content later approved by users
- Percentage of blocked persistence attempts judged correct
- Latency overhead per scanned source
- Developer integration time

### Launch targets

Initial launch targets should be set during implementation planning, but the MVP should only proceed if benchmark performance shows:

- strong coverage on known attacks,
- false positives low enough to avoid constant quarantine of benign examples,
- and limited measurable impact on clean-task completion quality.

## 22. Evaluation Plan

### Benchmark classes

1. Known prompt-injection payloads hidden in web and RAG content
2. Benign security articles that discuss prompt injection
3. Technical docs with imperative phrasing
4. Markdown/code samples containing instruction-like text
5. Mixed pages that contain both useful facts and hostile payloads
6. Persistence attempts targeting summaries, memory, or handoffs

### Required evaluation outputs

- per-category detection precision and recall,
- false positive breakdown by source type,
- task-completion comparison against an unprotected baseline,
- and review-action analytics for include, exclude, and reprocess-clean.

## 23. Rollout Plan

### Phase 1: Prototype

- Integrate intake scanning for retrieval and web fetch
- Implement rule engine and source-aware thresholds
- Build quarantine storage and end-of-task review summary

### Phase 2: Persistence defense

- Add blocked writes for summaries, memory, and handoffs
- Add retro-scan of previously stored artifacts

### Phase 3: Safer action handling

- Add deferred execution policy for irreversible external actions influenced by tainted content
- Add richer developer hooks and policy customization

### Phase 4: Platform expansion

- Add tool output and file/code scanning
- Add admin controls and broader runtime support

## 24. Risks

### Product risks

- Too many false positives may reduce trust and usefulness.
- Too little aggression may let sophisticated zombie attacks through.
- End-of-task review may feel too late for some workflows if downstream actions are not sufficiently protected.

### Technical risks

- Rule-based logic may underperform against subtle or obfuscated attacks.
- Advanced anomaly scoring may increase latency or complexity.
- Content provenance can be incomplete depending on the host framework.

### UX risks

- Users may ignore end-of-task reviews if they are too noisy.
- Reprocess-clean may remove useful context or fail to fully neutralize the attack.

## 25. Open Questions and Assumptions

### Assumptions made in this draft

- "Claude co-work" is treated as a Claude-centered human-plus-agent collaboration environment rather than a formally defined product surface.
- The first integration point is a plugin or adapter in the content-intake path, not a hosted standalone service.
- The MVP prioritizes retrieval and web-fetch content over tool output and user input.
- The product uses rule-based detection first, enhanced by anomaly and denoising-style techniques rather than a fully model-based classifier.
- Deferred handling of irreversible external actions is included as a light policy layer because downstream actions were identified as important risk areas.

### Open questions to resolve in the next revision

- What exact Claude integration surface should be supported first?
- What developer API shape is preferred for callbacks and review hooks?
- What content formats must be supported first beyond plain text and markdown?
- What latency budget is acceptable per content source?
- Should the product ship as open source, commercial SDK, or managed offering?
- How much of the review UX lives in the plugin host versus a companion service?

## 26. Decision Summary

The MVP for ZombieSlayer is a developer-first plugin for Claude-centered agent workflows that:

- scans web and retrieval content before context inclusion,
- quarantines suspicious sources without interrupting live flow,
- provides end-of-task review with include, exclude, and reprocess-clean,
- blocks suspicious persistence writes,
- retro-scans stored artifacts for contamination,
- and exposes provenance and customization hooks for developers.

This direction is deliberately opinionated: it optimizes for strong zombie-injection detection and persistence defense while preserving utility and minimizing real-time friction.

