import { createFileRoute } from "@tanstack/react-router";
import { AppShell } from "@/components/app-shell";
import { HelpCircle, Shield, Award, Cpu, Code2, Scale } from "lucide-react";

export const Route = createFileRoute("/about")({
  head: () => ({
    meta: [
      { title: "About Swarm Roster — AETHER-PQ" },
      { name: "description", content: "Details regarding compiled dependencies, compiler flags, and target hardware platforms for the post-quantum UAV security engine." },
    ],
  }),
  component: AboutPage,
});

function AboutPage() {
  const specGroups = [
    {
      title: "Core Metadata",
      icon: Shield,
      items: [
        { label: "Application Version", value: "1.0.0-RC1" },
        { label: "Protocol Suite Version", value: "1.0.0 (ACPE-hybrid)" },
        { label: "License Type", value: "MIT License" },
        { label: "Build Target Identifier", value: "aether-pq-armv7-a9" }
      ]
    },
    {
      title: "Compiler & Cryptography Build",
      icon: Code2,
      items: [
        { label: "C++ Compiler Target", value: "Clang++ 14.0.0 / GCC 9.3" },
        { label: "OpenSSL Toolkit", value: "OpenSSL 1.1.1u (18 May 2023)" },
        { label: "Post-Quantum Algorithms", value: "liboqs 0.8.0 (ML-KEM, ML-DSA)" },
        { label: "Build Flags", value: "-O3 -march=armv7-a -mfpu=neon-vfpv4" }
      ]
    },
    {
      title: "Target Hardware & OS Constraints",
      icon: Cpu,
      items: [
        { label: "Processor Architecture", value: "ARMv7 Cortex-A9 (Dual-core)" },
        { label: "Target Operating System", value: "Embedded Linux 4.4.19" },
        { label: "System RAM Ceiling", value: "256 MB RAM Budget" },
        { label: "Write Wear Minimization", value: "Buffered Ramdisks (tmpfs)" }
      ]
    },
    {
      title: "Simulation & Integration Layers",
      icon: Award,
      items: [
        { label: "Simulation Platform", value: "ns-3.35 Discrete Event Simulator" },
        { label: "Dual Interfaces Config", value: "eth0 (Control) / eth1 (Data telemetry)" },
        { label: "TreeKEM Library", value: "Native C++ TreeKEM group key exchange" },
        { label: "Audit Verifier Path", value: "verify_audit.ts Hash Chain Auditor" }
      ]
    }
  ];

  return (
    <AppShell
      eyebrow="Reference · About System"
      title="About Swarm Security Engine"
      breadcrumbs={[{ label: "Reference", to: "/system" }, { label: "About" }]}
    >
      <div className="space-y-6">
        {/* Intro Banner */}
        <div className="rounded-lg border border-border bg-card p-6 shadow-xs">
          <div className="flex items-start gap-4">
            <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
              <HelpCircle className="h-6 w-6" />
            </div>
            <div>
              <h1 className="text-[17px] font-semibold text-foreground">AETHER-PQ Security Engine</h1>
              <p className="mt-2 text-[13px] text-muted-foreground leading-relaxed max-w-3xl">
                AETHER-PQ is a research-grade post-quantum security governance platform designed specifically for mobile 
                autonomous drone swarms. It couples TreeKEM group membership rekeying with an Adaptive Cryptographic 
                Policy Engine (ACPE) to dynamically scale security overhead against battery constraints and latency 
                thresholds.
              </p>
              <p className="mt-3 text-[12px] font-medium text-warning border-l-2 border-warning/60 pl-3 leading-relaxed max-w-3xl">
                Note: The software architecture has been designed for compatibility with ARMv7 Cortex-A9 systems running Linux 4.4. Final compatibility and performance validation will be confirmed through execution and benchmarking on the target hardware.
              </p>
            </div>
          </div>
        </div>

        {/* Specifications Cards Grid */}
        <div className="grid gap-4 sm:grid-cols-2">
          {specGroups.map((group) => {
            const Icon = group.icon;
            return (
              <div key={group.title} className="rounded-lg border border-border bg-card p-5 shadow-xs">
                <div className="flex items-center gap-2.5 pb-3 border-b border-border/80">
                  <Icon className="h-4 w-4 text-primary" />
                  <h2 className="font-semibold text-foreground text-[13.5px]">{group.title}</h2>
                </div>
                <dl className="mt-4 space-y-3">
                  {group.items.map((item) => (
                    <div key={item.label} className="flex flex-wrap justify-between gap-2 text-[12px] leading-relaxed">
                      <dt className="text-muted-foreground">{item.label}</dt>
                      <dd className="font-mono text-foreground text-right">{item.value}</dd>
                    </div>
                  ))}
                </dl>
              </div>
            );
          })}
        </div>

        {/* Licensing & Research Info */}
        <div className="rounded-lg border border-border bg-card p-5 shadow-xs">
          <div className="flex items-center gap-2 pb-3 border-b border-border/80">
            <Scale className="h-4 w-4 text-primary" />
            <h2 className="font-semibold text-foreground text-[13.5px]">Academic Publication & Licensing</h2>
          </div>
          <p className="mt-4 text-[12.5px] text-muted-foreground leading-relaxed">
            The platform source and protocols are published under the MIT License for evaluation, research defenses, and conferences demonstrations.
          </p>
          <div className="mt-4 rounded-md bg-surface-2 p-3 text-[11px] font-mono text-muted-foreground leading-relaxed border border-border/60">
            Copyright (c) 2026 AETHER-PQ Authors.<br />
            Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files to deal in the Software without restriction...
          </div>
        </div>
      </div>
    </AppShell>
  );
}
