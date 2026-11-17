---
title: Mitch
layout: hextra-home
---

<div class="hx:mt-6 hx:mb-6">
{{< hextra/hero-headline >}}
  Know what is in your Vault
{{< /hextra/hero-headline >}}
</div>

<div class="hx:mb-12">
{{< hextra/hero-subtitle >}}
  Mitch scans a HashiCorp Vault cluster, read-only, and saves an encrypted inventory&nbsp;<br class="hx:sm:block hx:hidden" />you can report on, compare, check for risky policies and turn into Terraform.
{{< /hextra/hero-subtitle >}}
</div>

<div class="hx:mb-6">
{{< hextra/hero-button text="Get started" link="docs/saving-scans/" >}}
</div>

<div class="hx:mt-6"></div>

{{< hextra/feature-grid >}}
  {{< hextra/feature-card
    title="Scan, read-only"
    subtitle="Secrets engines, auth methods, plugins, namespaces, ACL policies and KV secret counts. Never secret values."
    link="docs/scanning/"
  >}}
  {{< hextra/feature-card
    title="Reports and diffs"
    subtitle="A summary of one scan in Markdown or JSON, and what changed between two scans."
    link="docs/reports/"
  >}}
  {{< hextra/feature-card
    title="Policy findings"
    subtitle="Root-equivalent grants, self-escalation and denies that do not block what they seem to. Fail CI with --fail-on."
    link="docs/findings/"
  >}}
  {{< hextra/feature-card
    title="Terraform"
    subtitle="Writes Terraform with import blocks, so Terraform can adopt your existing Vault setup."
    link="docs/terraform/"
  >}}
  {{< hextra/feature-card
    title="Encrypted at rest"
    subtitle="Every saved scan is encrypted with a key from your passphrase. A stolen database is unreadable."
    link="docs/data-security/"
  >}}
  {{< hextra/feature-card
    title="One binary"
    subtitle="A single Go binary for macOS, Linux and Windows, plus a small Docker image. Nothing else to install."
    link="docs/docker/"
  >}}
{{< /hextra/feature-grid >}}
