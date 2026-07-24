# Landing-page generation prompt — wptracked.com

Paste the block below into your generator (Devin, v0, etc.) to produce the
WPTracked marketing site. It is self-contained.

---

> **Build a single-page marketing website for a product called "WPTracked"
> (domain: wptracked.com), a product by Varry LLC.**
>
> **Product to describe.** WPTracked is an automated, strictly **read-only**
> server + WordPress health & security auditor. It runs *on the customer's own
> server* through a **Devin outpost**, inspects the VPS and every WordPress site,
> and e-mails a branded `[HEALTHY]`/`[ALERT]` report (HTML body + PDF). It never
> modifies anything. Link prominently to the GitHub repo:
> **https://github.com/varry-llc/WPTracked**.
>
> **Sections (in order):**
> 1. **Hero** — product name, one-line value prop ("Know your WordPress fleet is
>    healthy — before your visitors do."), primary CTA "View on GitHub"
>    (→ https://github.com/varry-llc/WPTracked), secondary CTA "See a sample report".
> 2. **The problem** — silent drift: expiring certs, un-patched plugins/CVEs,
>    weak file permissions, password root SSH, brute-force noise.
> 3. **What it checks** — host (disk/inodes, TLS, OS updates, reboot), WordPress
>    core checksums, plugin/theme updates, vulnerability + **CISA KEV** scan, a
>    WordPress security best-practices audit, and log/SSH intrusion analysis.
> 4. **How it works** — a 4-step pipeline (collect → scan → render → send) shown
>    as an animated flow; emphasise the **Devin outpost** execution and the
>    **provider-agnostic** e-mail (EmailIt / SMTP / SendGrid / Mailgun / Resend).
> 5. **Security posture** — read-only, fail-closed, no secrets logged, locked &
>    idempotent runs. Make this a first-class selling point.
> 6. **Reports** — show the branded HTML/PDF, the `[ALERT]`/`[HEALTHY]` verdict,
>    and logical grouping.
> 7. **Scheduling & integrations** — cron / systemd timer / Devin Automation;
>    server-only vs server+WordPress scope; per-check toggles.
> 8. **Roadmap** — a *future* opt-in "approved automated updates with e-mailed
>    reports" mode (clearly labelled not-yet-available).
> 9. **Footer** — © Varry LLC, GitHub link, wptracked.com.
>
> **Technical requirements (must all be met):**
> - **Semantic HTML5** (`header`/`main`/`section`/`article`/`nav`/`footer`),
>   correct heading hierarchy, descriptive `alt` text.
> - **SEO**: `<title>`, meta description, canonical, Open Graph + Twitter cards,
>   and **JSON-LD** structured data (`SoftwareApplication` / `Organization`).
> - **Accessibility (WCAG 2.1 AA)**: keyboard navigable, visible focus states,
>   ARIA only where needed, AA color contrast, respects
>   `prefers-reduced-motion` and `prefers-color-scheme`.
> - **Single self-contained file**: put all CSS in one inline `<style>` and all
>   JS in one inline `<script type="module">`. No external CSS/JS files — the
>   output must be copy-paste-and-open.
> - **Vanilla CSS only** (no framework), **BEM** naming
>   (`block__element--modifier`), CSS custom properties for the palette,
>   per-component style sections, mobile-first **responsive** layout.
> - **Vanilla JavaScript only**, written as **encapsulated modules within the
>   single inline module** (no globals; each behavior is its own
>   IIFE/closure/exported function with a clean init API).
> - **Animation**: use **CSS animations/transitions** for simple effects
>   (hover, reveal-on-scroll via `IntersectionObserver`); use **GSAP**
>   (with `ScrollTrigger`) for the complex sequenced/scroll-driven animations
>   (hero entrance, the pipeline flow, parallax). Gate ALL motion behind
>   `prefers-reduced-motion: reduce`.
> - **Performance**: no render-blocking resources, lazy-load below-the-fold
>   imagery, system font stack or `font-display: swap`, load GSAP deferred, keep
>   Lighthouse (perf/a11y/SEO) ≥ 95.
>
> **Visual theme — Sergio Leone spaghetti-western.** Evoke the *mood and era* of
> a Sergio Leone film (e.g. the sun-bleached, dusty, wide-horizon "man with no
> name" aesthetic): warm sand/ochre/rust palette, big-sky vistas, dramatic
> wide-shot framing, weathered serif display type, high-contrast lighting, a
> lone-gunslinger-at-high-noon tension. The knowing joke: the "outpost"
> technology is our frontier outpost on the lawless WordPress frontier —
> WPTracked is the quiet marshal keeping the town safe. Do **NOT** reproduce any
> copyrighted film artwork, posters, stills, character likenesses, or logos —
> create original artwork/illustration inspired by the era only.
>
> **Audio — handle legally.** A classic Leone-style musical sting would be fun,
> but **do not embed any copyrighted audio** (e.g. Ennio Morricone recordings)
> without a license. Instead: add an **optional, non-autoplaying** audio control
> (a clearly labelled play/mute button, off by default, keyboard-accessible,
> respecting reduced-motion/`prefers-reduced-motion` and not blocking content),
> and wire it to a **royalty-free / public-domain / original** western-style clip
> the owner supplies. Leave a clearly commented placeholder
> (`/* replace with a properly licensed audio asset */`) rather than shipping any
> unlicensed track. Never autoplay audio.
>
> **Deliverable:** exactly **one `index.html`** file (inline CSS + inline
> module JS + inline SVG, GSAP via CDN), with brief comments explaining
> structure, ready to copy-paste and open in a browser. Keep the GitHub link
> (https://github.com/varry-llc/WPTracked) visible in the hero and footer.
