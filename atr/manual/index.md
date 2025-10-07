# Apache Trusted Releases (ATR) manual

Welcome to the user and developer manuals for the **Apache Trusted Releases** (ATR) platform.

NOTE: This user manual is a work in progress.

## Introduction to ATR

### What is ATR?

ATR is a platform through which committees of [Apache Software Foundation](https://www.apache.org/) (ASF) projects can make official ASF software releases. Official ASF releases are endorsed as an "[act of the Foundation](https://www.apache.org/legal/release-policy.html#release-definition)". It is therefore important that the foundation - its board, members, committees, and contributors - and the general public can have confidence in the releases.

What sort of confidence in releases is required? All parties need to be certain that the software available for download is exactly that which was intended to be published by the applicable project management committee (PMC), and by the foundation. This may seem trivial, but software distribution platforms such as ATR now operate in extremely adversarial environments. In the years before ATR was launched, [supply chain attacks](https://en.wikipedia.org/wiki/Supply_chain_attack) on open source software became [far more frequent and more sophisticated](https://www.sonatype.com/state-of-the-software-supply-chain/2024/scale).

The end goal of supply chain attacks is almost always to cause harm to users. Harms are wide-ranging and can include unwanted features, the extraction of money from the user, surveillance and exfiltration of data, and material damage. The exact methods of supply chain attacks vary, but the general principle is to modify some legitimate software between the time that it was written and the time that it was received by the end user, without the modification being noticed. If software is distributed to the end user through a distribution platform, and the distribution platform has security weaknesses, then exploiting those security weaknesses is attractive to attackers.

**The goal of ATR is to deter and minimize the risk of supply chain attacks.** ATR does not ensure the quality of software received legitimately from PMCs. The foundation as a whole, of course, has the goal of establishing the highest quality of software to be produced, but that is not the responsibility of ATR as a platform. The responsibility of ATR is to ensure that the software it distributes to end users is the legitimate submission of each of our constituent PMCs. In other words, for you, the end user of ASF software, the goal is that you receive software that was not modified by an attacker to cause you harm.

### Who are ATR users?

There are two kinds of ATR user: our participants who use ATR to publish their software, and ASF software end users who use ATR to obtain that software. This guide is primarily written for the former, our participants who are publishing their software. Skilled end users may be interested in reading this guide for the purpose of learning the purported security claims that we make, reviewing the implementation strategies that we picked to achieve them, and ascertaining the likelihood that those claims were achieved.

It is important to remember that security is a complex and rapidly evolving field, as the parties are involved in an ongoing game of cat and mouse. Software producers are often under tight budget and time constraints, forced to prioritize properties other than security, working in environments known to be insecure, using practices known to be suboptimal, and deploying to architectures with known vulnerabilities. Attackers race to find mistakes before producers, and use them to their own ends. They hope not to be discovered, and often use sophisticated techniques to cover their tracks. When they are discovered, the producers patch the mistakes only to find that the attackers infiltrate via another route. The more that we use software in our lives, in our industries, and in our societies, the greater the rewards for attackers and the greater the motivation to perform these attacks.

In this guide, we document how ATR is situated in this complex security landscape. But we also document the day-to-day operation of ATR: which forms to use, which buttons to press, how to make the release process simple, convenient, and well understood, but always with the goal of producing software as it was intended to be.

### What is ATR like to use?

Security of ASF release processes is the primary goal of ATR, but outstanding usability is also necessary to achieve this goal. The ASF has been in operation since 1999, and has needed release procedures from the very start. ATR is the next step in the evolution of those procedures, but the release managers (RMs) responsible for releasing ASF software are accustomed to the existing procedures. Convenience is a visceral property with a disproportionate effect. If ATR were secure but less convenient, there would be less conspicuous motivation for RMs to migrate to the new platform. Migration always has a cost, and the benefits must outweigh that cost. If ATR is both more secure and more convenient than the old way of doing things, RMs are likely to migrate even if the one-time cost is relatively high. We aim to make ATR secure and convenient, and also to lower the cost of migration as much as possible.

As such, we offer a choice of interfaces when using ATR. We have a web-based interface, a JSON API, and a command-line interface (CLI). We try to make functionality as available as possible across all three interfaces. We also plan to add a text user interface (TUI), which is a kind of hybrid of the web-based interface and the CLI. The intention of having so many interfaces is that users can choose the ones which are most convenient for them at each step.

Speaking of steps, what are the steps to release software on ATR? We have kept this as simple as possible. First, the project's participants compose a candidate release from existing files. Second, as per ASF policy, the PMC votes on that candidate release. Third, if the vote passes, the PMC officially publishes and announces the erstwhile candidate release as a finished, official release. That's the whole process for the majority of PMCs, but of course there are many details and considerations along the way, and some edge cases and alternatives as well.

### Who develops ATR?

ATR is developed by ASF Tooling, an ASF initiative launched in 2025, and responsible for streamlining development, automating repetitive tasks, reducing technical debt, and enhancing collaboration throughout the ASF. The source code of ATR is developed in public as open source code, and ASF Tooling welcomes high quality contributions to the codebase from external contributors, whether from existing ASF contributors or members of the public. Because of the stringent security and usability requirements, Tooling accepts only very high quality contributions, and carefully reviews all submitted code. As a consequence, contributors must be well versed in the workings of ATR, and therefore this manual contains an extensive developer section to facilitate understanding.

This manual is an integral part of ATR, and contributions to this manual are therefore treated like any of the rest of the code. We welcome all types of contribution, whether that be writing entire pages or correcting small typographical errors. The easiest path to contribution is to [create a pull request](https://github.com/apache/tooling-trusted-release/compare) on [our GitHub repository](https://github.com/apache/tooling-trusted-release). You can also [email patches](https://lists.apache.org/list.html?dev@tooling.apache.org). Read our [contribution guide](contribution.html) for more details.
