# Free-use policy

Argus itself is MIT-licensed software. You can use, modify, and run this local desktop app without paying Argus.

## Collector cost model

Argus collectors are designed to be free to run:

- Keyless public-source collectors use public pages, public feeds, public APIs, or generated review links without requiring payment.
- Optional credentialed collectors use user-provided keys from services that offer free developer access or free public API tiers. These keys are stored in the operating-system credential vault.
- Argus does not require paid SaaS subscriptions, hosted Argus accounts, paid proxy networks, CAPTCHA bypass services, or commercial enrichment APIs.

## Social media boundary

Social platform coverage is split into two lawful categories:

- Live collectors where a platform exposes free public data without a paid API key, such as Reddit public profile JSON, Bluesky public AppView, Mastodon public instance APIs, Hacker News Firebase, GitHub/GitLab public APIs, Keybase public profiles, Gravatar public profiles, and YouTube public channel RSS/page metadata.
- Unverified lead collectors for platforms that restrict free API access or require login for reliable live data, such as X, Instagram, Facebook, Threads, TikTok, LinkedIn, Pinterest, Snapchat, Telegram, Twitch, Medium, Substack, Tumblr, Flickr, SoundCloud, Vimeo, Patreon, Linktree, and similar public profile URL patterns.

Argus does not bypass login requirements, scrape private content, defeat rate limits, or claim that matching handles prove identity. Platform URLs are review leads unless a collector directly verifies a public profile through a public endpoint.

## Operator responsibility

Third-party services can change their free tiers, rate limits, API policies, and terms of service. Argus avoids paid dependencies, but operators remain responsible for checking whether their use of each public source is lawful and permitted for their investigation, jurisdiction, and volume.
